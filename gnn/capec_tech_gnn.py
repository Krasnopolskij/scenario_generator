from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from dotenv import load_dotenv
from py2neo import Graph
from sentence_transformers import SentenceTransformer
from sklearn.metrics import roc_auc_score, roc_curve
from torch_geometric.nn import GCNConv
from tqdm import tqdm


@dataclass
class GNNConfig:
    """Конфигурация пайплайна GNN для CAPEC→Technique."""

    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_db: str = "neo4j"

    # Текстовая модель для эмбеддингов
    sentence_model_name: str = "sentence-transformers/all-mpnet-base-v2"

    # Параметры GNN
    hidden_dim: int = 128
    out_dim: int = 64
    epochs: int = 60
    lr: float = 1e-3
    weight_decay: float = 5e-4

    # Отбор предсказанных рёбер
    top_k: int = 2
    min_score: float = 0.7

    # Режим работы GNN: mlp (через MLP-предиктор) или dot (через cosine-сходство)
    mode: str = "dot"

    # Прочее
    device: str = "cpu"
    seed: int = 29
    dry_run: bool = False

    @classmethod
    def from_env(cls, args: Optional[argparse.Namespace] = None) -> "GNNConfig":
        neo4j_uri = os.getenv("NEO4J_URI") or "bolt://localhost:7687"
        neo4j_user = os.getenv("NEO4J_USER") or "neo4j"
        neo4j_password = os.getenv("NEO4J_PASSWORD") or "neo4j"
        neo4j_db = os.getenv("NEO4J_DATABASE") or "neo4j"

        def _int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, default))
            except Exception:
                return default

        def _float(name: str, default: float) -> float:
            try:
                return float(os.getenv(name, default))
            except Exception:
                return default

        def _bool(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        sentence_model_name = os.getenv(
            "GNN_SENTENCE_MODEL", "sentence-transformers/all-mpnet-base-v2"
        )
        hidden_dim = _int("GNN_HIDDEN_DIM", 128)
        out_dim = _int("GNN_OUT_DIM", 64)
        epochs = _int("GNN_EPOCHS", 60)
        lr = _float("GNN_LR", 1e-3)
        weight_decay = _float("GNN_WEIGHT_DECAY", 5e-4)
        top_k = _int("GNN_TOP_K", 2)
        min_score = _float("GNN_MIN_SCORE", 0.5)
        seed = _int("GNN_SEED", 42)
        mode = (os.getenv("GNN_MODE", "dot") or "dot").strip().lower()
        if mode not in {"mlp", "dot"}:
            mode = "dot"

        default_device = "cuda" if torch.cuda.is_available() else "cpu"
        device = os.getenv("GNN_DEVICE", default_device)

        dry_run_env = _bool("GNN_DRY_RUN", False)
        dry_run = dry_run_env

        if args is not None:
            if getattr(args, "epochs", None) is not None:
                epochs = int(args.epochs)
            if getattr(args, "top_k", None) is not None:
                top_k = int(args.top_k)
            if getattr(args, "min_score", None) is not None:
                min_score = float(args.min_score)
            if getattr(args, "sentence_model", None) is not None:
                sentence_model_name = str(args.sentence_model)
            if getattr(args, "device", None) is not None:
                device = str(args.device)
            if getattr(args, "dry_run", None) is True:
                dry_run = True
            if getattr(args, "mode", None) is not None:
                mode = str(args.mode).strip().lower()

        return cls(
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            neo4j_db=neo4j_db,
            sentence_model_name=sentence_model_name,
            hidden_dim=hidden_dim,
            out_dim=out_dim,
            epochs=epochs,
            lr=lr,
            weight_decay=weight_decay,
            top_k=top_k,
            min_score=min_score,
            mode=mode,
            device=device,
            seed=seed,
            dry_run=dry_run,
        )


class GCNEncoder(nn.Module):
    """Двухслойный GCN-энкодер для узлов."""

    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        return x


class LinkPredictor(nn.Module):
    """MLP-predictor для оценки вероятности ребра."""

    def __init__(self, in_channels: int, hidden_channels: int = 64):
        super().__init__()
        self.lin1 = nn.Linear(in_channels * 3, hidden_channels)
        self.lin2 = nn.Linear(hidden_channels, 1)

    def forward(self, z_src: torch.Tensor, z_dst: torch.Tensor) -> torch.Tensor:
        h = torch.cat([z_src, z_dst, z_src * z_dst], dim=-1)
        h = F.relu(self.lin1(h))
        h = self.lin2(h).view(-1)
        return torch.sigmoid(h)


class CapecTechniqueDataset:
    """Загрузка подграфа CAPEC↔Technique из Neo4j и подготовка данных."""

    def __init__(self, graph: Graph):
        self.graph = graph

        self.nodes: List[Dict[str, object]] = []
        self.neo_id_to_idx: Dict[int, int] = {}
        self.capec_indices: List[int] = []
        self.tech_indices: List[int] = []

        self.edge_index: Optional[torch.Tensor] = None
        self.pos_pairs: List[Tuple[int, int]] = []
        self.pos_set: set[Tuple[int, int]] = set()
        self.pos_by_cap: Dict[int, List[int]] = {}
        self.neg_pool_by_cap: Dict[int, List[int]] = {}
        self.existing_pred_pairs: set[Tuple[int, int]] = set()
        self.base_degree_capec: Dict[int, int] = {}

        self.x: Optional[torch.Tensor] = None

    def _load_nodes(self) -> None:
        print("Загрузка узлов CAPEC и Technique из Neo4j…")

        cap_query = """
        MATCH (c:CAPEC)
        RETURN id(c) AS neo_id, c.identifier AS identifier,
               c.name AS name, c.description AS description
        """
        cap_records = list(self.graph.run(cap_query))

        tech_query = """
        MATCH (t:Technique)
        RETURN id(t) AS neo_id, t.identifier AS identifier,
               t.name AS name, t.description AS description
        """
        tech_records = list(self.graph.run(tech_query))

        idx = 0
        for rec in cap_records:
            neo_id = int(rec["neo_id"])
            node = {
                "idx": idx,
                "neo_id": neo_id,
                "identifier": rec.get("identifier"),
                "name": rec.get("name"),
                "description": rec.get("description"),
                "kind": "CAPEC",
            }
            self.nodes.append(node)
            self.neo_id_to_idx[neo_id] = idx
            self.capec_indices.append(idx)
            self.base_degree_capec[idx] = 0
            idx += 1

        for rec in tech_records:
            neo_id = int(rec["neo_id"])
            node = {
                "idx": idx,
                "neo_id": neo_id,
                "identifier": rec.get("identifier"),
                "name": rec.get("name"),
                "description": rec.get("description"),
                "kind": "Technique",
            }
            self.nodes.append(node)
            self.neo_id_to_idx[neo_id] = idx
            self.tech_indices.append(idx)
            idx += 1

        print(
            f"Узлов CAPEC: {len(self.capec_indices)}, "
            f"узлов Technique: {len(self.tech_indices)}, "
            f"всего узлов: {len(self.nodes)}"
        )

    def _load_edges(self) -> None:
        print("Загрузка существующих рёбер CAPEC_TO_TECHNIQUE…")
        edge_query = """
        MATCH (c:CAPEC)-[:CAPEC_TO_TECHNIQUE]->(t:Technique)
        RETURN id(c) AS cap_id, id(t) AS tech_id
        """
        records = list(self.graph.run(edge_query))

        src: List[int] = []
        dst: List[int] = []

        for rec in records:
            cap_neo = int(rec["cap_id"])
            tech_neo = int(rec["tech_id"])
            cap_idx = self.neo_id_to_idx.get(cap_neo)
            tech_idx = self.neo_id_to_idx.get(tech_neo)
            if cap_idx is None or tech_idx is None:
                continue
            pair = (cap_idx, tech_idx)
            if pair in self.pos_set:
                continue
            self.pos_pairs.append(pair)
            self.pos_set.add(pair)
            self.base_degree_capec[cap_idx] = self.base_degree_capec.get(cap_idx, 0) + 1
            self.pos_by_cap.setdefault(cap_idx, []).append(tech_idx)

            # Делаем граф неориентированным для GCN
            src.append(cap_idx)
            dst.append(tech_idx)
            src.append(tech_idx)
            dst.append(cap_idx)

        if not self.pos_pairs:
            print("В базе нет рёбер CAPEC_TO_TECHNIQUE, данные для обучения отсутствуют.")
        else:
            print(f"Положительных рёбер CAPEC_TO_TECHNIQUE: {len(self.pos_pairs)}")

        self.edge_index = (
            torch.tensor([src, dst], dtype=torch.long) if src and dst else None
        )

        # Формируем пул техник, не связанных с данным CAPEC, для отрицательного сэмплинга
        for cap_idx in self.capec_indices:
            pos_for_cap = set(self.pos_by_cap.get(cap_idx, []))
            self.neg_pool_by_cap[cap_idx] = [
                t for t in self.tech_indices if t not in pos_for_cap
            ]

        print("Загрузка уже существующих предсказанных рёбер CAPEC_TO_TECHNIQUE_PRED…")
        pred_query = """
        MATCH (c:CAPEC)-[:CAPEC_TO_TECHNIQUE_PRED]->(t:Technique)
        RETURN id(c) AS cap_id, id(t) AS tech_id
        """
        pred_records = list(self.graph.run(pred_query))
        for rec in pred_records:
            cap_neo = int(rec["cap_id"])
            tech_neo = int(rec["tech_id"])
            cap_idx = self.neo_id_to_idx.get(cap_neo)
            tech_idx = self.neo_id_to_idx.get(tech_neo)
            if cap_idx is None or tech_idx is None:
                continue
            self.existing_pred_pairs.add((cap_idx, tech_idx))

        print(
            f"Уже существующих CAPEC_TO_TECHNIQUE_PRED: "
            f"{len(self.existing_pred_pairs)}"
        )

    def _build_features(self, cfg: GNNConfig) -> None:
        print(f"Построение текстовых эмбеддингов с моделью {cfg.sentence_model_name!r}…")
        sentences: List[str] = []
        type_features: List[List[float]] = []

        for node in self.nodes:
            name = str(node.get("name") or "").strip()
            desc = str(node.get("description") or "").strip()
            if desc and not desc.endswith("."):
                text = f"{name}. {desc}"
            elif desc:
                text = f"{name} {desc}"
            else:
                text = name
            sentences.append(text or node.get("identifier") or "")

            kind = node.get("kind")
            if kind == "CAPEC":
                type_features.append([1.0, 0.0])
            else:
                type_features.append([0.0, 1.0])

        model = SentenceTransformer(cfg.sentence_model_name, device=cfg.device)
        embeddings = model.encode(
            sentences,
            batch_size=16,
            show_progress_bar=True,
            convert_to_numpy=True,
        )

        type_arr = np.asarray(type_features, dtype=np.float32)
        if type_arr.shape[0] != embeddings.shape[0]:
            raise RuntimeError("Размерности type_features и embeddings не совпадают")

        feats = np.concatenate([embeddings, type_arr], axis=1)
        self.x = torch.from_numpy(feats).float()

        print(
            f"Размерность признаков: {self.x.shape[1]} "
            f"(эмбеддинг: {embeddings.shape[1]}, тип: 2)"
        )

    def load(self, cfg: GNNConfig) -> None:
        self._load_nodes()
        self._load_edges()
        if not self.nodes:
            raise RuntimeError("Не найдено ни одного узла CAPEC/Technique")
        self._build_features(cfg)

    def candidate_capec_indices(self) -> List[int]:
        """CAPEC без исходных рёбер CAPEC_TO_TECHNIQUE (по базе на момент запуска)."""
        return [
            idx
            for idx in self.capec_indices
            if self.base_degree_capec.get(idx, 0) == 0
        ]


def set_random_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _roc_json_path() -> Path:
    return Path(__file__).resolve().parent / "roc_auc_last.json"


def save_roc_auc_json(
    cfg: GNNConfig,
    status: str,
    auc: Optional[float] = None,
    fpr: Optional[np.ndarray] = None,
    tpr: Optional[np.ndarray] = None,
    thresholds: Optional[np.ndarray] = None,
    meta: Optional[Dict[str, object]] = None,
    error: Optional[str] = None,
) -> None:
    def _safe_float_list(values: Optional[np.ndarray]) -> List[Optional[float]]:
        if values is None:
            return []
        try:
            arr = np.asarray(values, dtype=np.float64)
        except Exception:
            return []
        out: List[Optional[float]] = []
        for val in arr.tolist():
            try:
                fval = float(val)
            except Exception:
                out.append(None)
                continue
            if math.isfinite(fval):
                out.append(fval)
            else:
                out.append(None)
        return out

    payload: Dict[str, object] = {
        "status": status,
        "auc": float(auc) if auc is not None else None,
        "fpr": _safe_float_list(fpr),
        "tpr": _safe_float_list(tpr),
        "thresholds": _safe_float_list(thresholds),
        "error": error,
        "meta": meta or {},
    }
    payload["meta"].setdefault("created_at", datetime.now(timezone.utc).isoformat())
    payload["meta"].setdefault("mode", cfg.mode)
    payload["meta"].setdefault("sentence_model", cfg.sentence_model_name)
    payload["meta"].setdefault("epochs", cfg.epochs)
    payload["meta"].setdefault("seed", cfg.seed)

    path = _roc_json_path()
    try:
        path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2, allow_nan=False),
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"Не удалось сохранить ROC-AUC JSON ({path}): {exc}")


def sample_negative_pairs(
    dataset: CapecTechniqueDataset,
    pos_pairs: Sequence[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    """Отрицательный сэмплинг: для каждого CAPEC выбирается техника, не связанная с ним."""
    neg_pairs: List[Tuple[int, int]] = []
    for cap_idx, _ in pos_pairs:
        pool = dataset.neg_pool_by_cap.get(cap_idx) or []
        if not pool:
            continue
        tech_neg = random.choice(pool)
        neg_pairs.append((cap_idx, tech_neg))
    return neg_pairs


def train_gnn_mlp(
    dataset: CapecTechniqueDataset,
    cfg: GNNConfig,
) -> Tuple[GCNEncoder, LinkPredictor, torch.Tensor]:
    if dataset.edge_index is None or not dataset.pos_pairs:
        raise RuntimeError("Недостаточно данных для обучения модели GNN")
    if dataset.x is None:
        raise RuntimeError("Признаки узлов не построены")

    device = torch.device(cfg.device)
    x = dataset.x.to(device)
    edge_index = dataset.edge_index.to(device)

    encoder = GCNEncoder(
        in_channels=x.size(1),
        hidden_channels=cfg.hidden_dim,
        out_channels=cfg.out_dim,
    ).to(device)
    predictor = LinkPredictor(
        in_channels=cfg.out_dim, hidden_channels=cfg.hidden_dim
    ).to(device)

    optimizer = torch.optim.Adam(
        list(encoder.parameters()) + list(predictor.parameters()),
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )

    pos_pairs = dataset.pos_pairs
    num_pos = len(pos_pairs)
    if num_pos < 2:
        raise RuntimeError("Слишком мало положительных рёбер для обучения модели GNN")

    # Разбивка на train/test для оценки ROC-AUC
    perm = torch.randperm(num_pos)
    split = int(num_pos * 0.8)
    if split <= 0 or split >= num_pos:
        split = num_pos - 1
    train_idx = perm[:split]
    test_idx = perm[split:]

    pos_train = [pos_pairs[i] for i in train_idx.tolist()]
    pos_test = [pos_pairs[i] for i in test_idx.tolist()]

    pos_tensor = torch.tensor(pos_train, dtype=torch.long, device=device)
    pos_labels = torch.ones(len(pos_train), dtype=torch.float32, device=device)

    print(
        f"Запуск обучения GNN (режим mlp): эпох {cfg.epochs}, "
        f"положительных рёбер всего {num_pos}, train {len(pos_train)}, test {len(pos_test)}"
    )

    for epoch in range(1, cfg.epochs + 1):
        encoder.train()
        predictor.train()
        optimizer.zero_grad()

        z = encoder(x, edge_index)

        # Положительные примеры (train)
        pos_src = pos_tensor[:, 0]
        pos_dst = pos_tensor[:, 1]
        pos_scores = predictor(z[pos_src], z[pos_dst])

        # Отрицательные примеры (train, пересэмплируем на каждой эпохе)
        neg_pairs = sample_negative_pairs(dataset, pos_train)
        neg_tensor = torch.tensor(neg_pairs, dtype=torch.long, device=device)
        neg_labels = torch.zeros(len(neg_pairs), dtype=torch.float32, device=device)
        neg_src = neg_tensor[:, 0]
        neg_dst = neg_tensor[:, 1]
        neg_scores = predictor(z[neg_src], z[neg_dst])

        scores = torch.cat([pos_scores, neg_scores], dim=0)
        labels = torch.cat([pos_labels, neg_labels], dim=0)

        loss = F.binary_cross_entropy(scores, labels)
        loss.backward()
        optimizer.step()

        if epoch % 10 == 0 or epoch == 1 or epoch == cfg.epochs:
            with torch.no_grad():
                preds = (scores >= 0.5).float()
                acc = (preds == labels).float().mean().item()
            print(
                f"[epoch {epoch:03d}/{cfg.epochs}] loss={loss.item():.4f}, "
                f"acc={acc:.4f}"
            )

    encoder.eval()
    with torch.no_grad():
        z = encoder(x, edge_index)

    # Оценка ROC-AUC на отложенной выборке
    if pos_test:
        neg_test_pairs = sample_negative_pairs(dataset, pos_test)
        meta = {
            "pos_total": len(pos_pairs),
            "pos_test": len(pos_test),
            "neg_test": len(neg_test_pairs),
        }
        if not neg_test_pairs:
            print(
                "Недостаточно отрицательных примеров для ROC-AUC, результаты не сохранены."
            )
            save_roc_auc_json(
                cfg,
                status="no_test_data",
                meta=meta,
                error="Недостаточно отрицательных примеров для ROC-AUC.",
            )
            z_cpu = z.detach().cpu()
            return encoder, predictor, z_cpu
        pos_test_tensor = torch.tensor(pos_test, dtype=torch.long, device=device)
        neg_test_tensor = torch.tensor(neg_test_pairs, dtype=torch.long, device=device)
        with torch.no_grad():
            pos_src_t = pos_test_tensor[:, 0]
            pos_dst_t = pos_test_tensor[:, 1]
            neg_src_t = neg_test_tensor[:, 0]
            neg_dst_t = neg_test_tensor[:, 1]
            pos_scores_t = predictor(z[pos_src_t], z[pos_dst_t]).cpu().numpy()
            neg_scores_t = predictor(z[neg_src_t], z[neg_dst_t]).cpu().numpy()
        y_scores = np.concatenate([pos_scores_t, neg_scores_t])
        y_true = np.concatenate(
            [np.ones_like(pos_scores_t), np.zeros_like(neg_scores_t)]
        )
        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_scores, drop_intermediate=False)
            auc = roc_auc_score(y_true, y_scores)
            print(
                f"Оценка ROC-AUC (режим mlp): {auc:.4f} "
                f"(pos={len(pos_test)}, neg={len(neg_test_pairs)})"
            )
            save_roc_auc_json(
                cfg,
                status="ok",
                auc=auc,
                fpr=fpr,
                tpr=tpr,
                thresholds=thresholds,
                meta=meta,
            )
        except Exception as e:
            print(f"Не удалось посчитать ROC-AUC: {e}")
            save_roc_auc_json(
                cfg,
                status="error",
                meta=meta,
                error=f"Не удалось посчитать ROC-AUC: {e}",
            )
    else:
        print(
            "Недостаточно данных для выделения отложенной выборки, ROC-AUC не рассчитан."
        )
        save_roc_auc_json(
            cfg,
            status="no_test_data",
            meta={"pos_total": len(pos_pairs), "pos_test": 0, "neg_test": 0},
            error="Недостаточно данных для выделения отложенной выборки.",
        )

    z_cpu = z.detach().cpu()
    return encoder, predictor, z_cpu


def train_gnn_dot(
    dataset: CapecTechniqueDataset,
    cfg: GNNConfig,
) -> Tuple[GCNEncoder, Optional[LinkPredictor], torch.Tensor]:
    if dataset.edge_index is None or not dataset.pos_pairs:
        raise RuntimeError("Недостаточно данных для обучения модели GNN")
    if dataset.x is None:
        raise RuntimeError("Признаки узлов не построены")

    device = torch.device(cfg.device)
    x = dataset.x.to(device)
    edge_index = dataset.edge_index.to(device)

    encoder = GCNEncoder(
        in_channels=x.size(1),
        hidden_channels=cfg.hidden_dim,
        out_channels=cfg.out_dim,
    ).to(device)

    optimizer = torch.optim.Adam(
        encoder.parameters(),
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )

    pos_pairs = dataset.pos_pairs
    num_pos = len(pos_pairs)
    if num_pos < 2:
        raise RuntimeError("Слишком мало положительных рёбер для обучения модели GNN")

    perm = torch.randperm(num_pos)
    split = int(num_pos * 0.8)
    if split <= 0 or split >= num_pos:
        split = num_pos - 1
    train_idx = perm[:split]
    test_idx = perm[split:]

    pos_train = [pos_pairs[i] for i in train_idx.tolist()]
    pos_test = [pos_pairs[i] for i in test_idx.tolist()]

    pos_tensor = torch.tensor(pos_train, dtype=torch.long, device=device)

    print(
        f"Запуск обучения GNN (режим dot): эпох {cfg.epochs}, "
        f"положительных рёбер всего {num_pos}, train {len(pos_train)}, test {len(pos_test)}"
    )

    eps = 1e-15

    def get_scores(z: torch.Tensor, edge_tensor: torch.Tensor) -> torch.Tensor:
        z_norm = F.normalize(z, p=2, dim=1)
        src = edge_tensor[:, 0]
        dst = edge_tensor[:, 1]
        return (z_norm[src] * z_norm[dst]).sum(dim=1)

    for epoch in range(1, cfg.epochs + 1):
        encoder.train()
        optimizer.zero_grad()

        z = encoder(x, edge_index)

        pos_scores = get_scores(z, pos_tensor)

        neg_pairs = sample_negative_pairs(dataset, pos_train)
        neg_tensor = torch.tensor(neg_pairs, dtype=torch.long, device=device)
        neg_scores = get_scores(z, neg_tensor)

        pos_loss = -torch.log(torch.sigmoid(pos_scores).clamp(min=eps, max=1 - eps)).mean()
        neg_loss = -torch.log((1 - torch.sigmoid(neg_scores)).clamp(min=eps, max=1 - eps)).mean()
        loss = pos_loss + neg_loss

        loss.backward()
        optimizer.step()

        if epoch % 10 == 0 or epoch == 1 or epoch == cfg.epochs:
            with torch.no_grad():
                all_scores = torch.cat([pos_scores, neg_scores], dim=0)
                labels = torch.cat(
                    [
                        torch.ones_like(pos_scores),
                        torch.zeros_like(neg_scores),
                    ],
                    dim=0,
                )
                preds = (torch.sigmoid(all_scores) >= 0.5).float()
                acc = (preds == labels).float().mean().item()
            print(
                f"[epoch {epoch:03d}/{cfg.epochs}] loss={loss.item():.4f}, "
                f"pos_loss={pos_loss.item():.4f}, neg_loss={neg_loss.item():.4f}, acc={acc:.4f}"
            )

    encoder.eval()
    with torch.no_grad():
        z = encoder(x, edge_index)

    if pos_test:
        neg_test_pairs = sample_negative_pairs(dataset, pos_test)
        meta = {
            "pos_total": len(pos_pairs),
            "pos_test": len(pos_test),
            "neg_test": len(neg_test_pairs),
        }
        if not neg_test_pairs:
            print(
                "Недостаточно отрицательных примеров для ROC-AUC, результаты не сохранены."
            )
            save_roc_auc_json(
                cfg,
                status="no_test_data",
                meta=meta,
                error="Недостаточно отрицательных примеров для ROC-AUC.",
            )
            z_cpu = z.detach().cpu()
            return encoder, None, z_cpu
        pos_test_tensor = torch.tensor(pos_test, dtype=torch.long, device=device)
        neg_test_tensor = torch.tensor(neg_test_pairs, dtype=torch.long, device=device)
        with torch.no_grad():
            pos_scores_t = torch.sigmoid(get_scores(z, pos_test_tensor)).cpu().numpy()
            neg_scores_t = torch.sigmoid(get_scores(z, neg_test_tensor)).cpu().numpy()
        y_scores = np.concatenate([pos_scores_t, neg_scores_t])
        y_true = np.concatenate(
            [np.ones_like(pos_scores_t), np.zeros_like(neg_scores_t)]
        )
        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_scores, drop_intermediate=False)
            auc = roc_auc_score(y_true, y_scores)
            print(
                f"Оценка ROC-AUC (режим dot): {auc:.4f} "
                f"(pos={len(pos_test)}, neg={len(neg_test_pairs)})"
            )
            save_roc_auc_json(
                cfg,
                status="ok",
                auc=auc,
                fpr=fpr,
                tpr=tpr,
                thresholds=thresholds,
                meta=meta,
            )
        except Exception as e:
            print(f"Не удалось посчитать ROC-AUC: {e}")
            save_roc_auc_json(
                cfg,
                status="error",
                meta=meta,
                error=f"Не удалось посчитать ROC-AUC: {e}",
            )
    else:
        print(
            "Недостаточно данных для выделения отложенной выборки, ROC-AUC не рассчитан."
        )
        save_roc_auc_json(
            cfg,
            status="no_test_data",
            meta={"pos_total": len(pos_pairs), "pos_test": 0, "neg_test": 0},
            error="Недостаточно данных для выделения отложенной выборки.",
        )

    z_cpu = z.detach().cpu()
    return encoder, None, z_cpu


def train_gnn(
    dataset: CapecTechniqueDataset,
    cfg: GNNConfig,
) -> Tuple[GCNEncoder, Optional[LinkPredictor], torch.Tensor]:
    if (cfg.mode or "mlp").lower() == "dot":
        return train_gnn_dot(dataset, cfg)
    return train_gnn_mlp(dataset, cfg)


def predict_new_edges(
    dataset: CapecTechniqueDataset,
    cfg: GNNConfig,
    z: torch.Tensor,
    predictor: Optional[LinkPredictor],
) -> List[Tuple[int, int, float]]:
    """Возвращает список (capec_idx, tech_idx, score) для новых рёбер."""
    device = torch.device(cfg.device)
    z = z.to(device)

    candidates_capec = dataset.candidate_capec_indices()
    if not candidates_capec:
        print(
            "Не найдено CAPEC без рёбер CAPEC_TO_TECHNIQUE, дополнение связей не требуется."
        )
        return []

    print(
        f"CAPEC без исходных CAPEC_TO_TECHNIQUE: {len(candidates_capec)}. "
        f"Для каждого узла будут отобраны топ-{cfg.top_k} наиболее вероятные связи."
    )

    tech_indices = torch.tensor(dataset.tech_indices, dtype=torch.long, device=device)
    z_tech = z[tech_indices]

    mode = (cfg.mode or "mlp").lower()
    if mode == "mlp":
        if predictor is None:
            raise RuntimeError("Ожидался обученный MLP-предиктор в режиме mlp")
        predictor = predictor.to(device)
        predictor.eval()
    else:
        z = F.normalize(z, p=2, dim=1)
        z_tech = z[tech_indices]

    new_edges: List[Tuple[int, int, float]] = []

    for cap_idx in tqdm(candidates_capec, desc="Link-prediction для CAPEC"):
        if mode == "mlp":
            cap_vec = z[cap_idx].unsqueeze(0).expand(z_tech.size(0), -1)
            with torch.no_grad():
                scores = predictor(cap_vec, z_tech)
        else:
            cap_vec = z[cap_idx].unsqueeze(0)
            with torch.no_grad():
                scores = torch.matmul(z_tech, cap_vec.t()).squeeze(1)
                scores = torch.sigmoid(scores)

        scores_np = scores.detach().cpu().numpy()
        order = np.argsort(-scores_np)

        selected = 0
        for j in order:
            tech_idx = int(tech_indices[j].item())
            score = float(scores_np[j])
            pair = (cap_idx, tech_idx)
            if (
                pair in dataset.pos_set
                or pair in dataset.existing_pred_pairs
                or score < cfg.min_score
            ):
                continue
            new_edges.append((cap_idx, tech_idx, score))
            selected += 1
            if selected >= cfg.top_k:
                break

    print(f"Всего новых кандидатов рёбер: {len(new_edges)}")
    return new_edges


def write_predicted_edges_to_neo4j(
    dataset: CapecTechniqueDataset,
    cfg: GNNConfig,
    new_edges: List[Tuple[int, int, float]],
) -> None:
    if not new_edges:
        print("Нет предсказанных рёбер для записи в Neo4j.")
        return

    print(
        f"Подготовка к записи в Neo4j {len(new_edges)} рёбер "
        f"CAPEC_TO_TECHNIQUE_PRED (top-{cfg.top_k}, score ≥ {cfg.min_score})."
    )

    edges_payload: List[Dict[str, object]] = []
    for cap_idx, tech_idx, score in new_edges:
        cap_node = dataset.nodes[cap_idx]
        tech_node = dataset.nodes[tech_idx]
        cap_id = cap_node.get("identifier")
        tech_id = tech_node.get("identifier")
        if not cap_id or not tech_id:
            continue
        edges_payload.append(
            {
                "cap_identifier": cap_id,
                "tech_identifier": tech_id,
                "score": float(score),
                "model": cfg.sentence_model_name,
            }
        )

    if not edges_payload:
        print("После фильтрации по identifier нечего записывать в Neo4j.")
        return

    cypher = """
    UNWIND $edges AS e
    MATCH (c:CAPEC {identifier: e.cap_identifier})
    MATCH (t:Technique {identifier: e.tech_identifier})
    MERGE (c)-[r:CAPEC_TO_TECHNIQUE_PRED]->(t)
    ON CREATE SET
      r.gnn_predicted = true,
      r.score = e.score,
      r.model = e.model,
      r.created_at = datetime()
    ON MATCH SET
      r.gnn_predicted = true,
      r.score = e.score,
      r.model = e.model,
      r.updated_at = datetime()
    """

    if cfg.dry_run:
        print(
            f"[DRY-RUN] Предсказанные рёбра не будут записаны. "
            f"Количество кандидатов после группировки: {len(edges_payload)}"
        )
        examples = edges_payload[:30]
        print("Примеры кандидатов:")
        for example in examples:
            print(
                f'{example["cap_identifier"]} --> {example["tech_identifier"]} '
                f'score={example["score"]:.4f}'
            )
        return

    print("Запись предсказанных рёбер в Neo4j…")
    start = time.time()
    dataset.graph.run(cypher, edges=edges_payload)
    dt = time.time() - start
    print(f"Запись в Neo4j завершена за {dt:.1f}с.")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "GNN для предсказания (дополнения) связей CAPEC→Technique.\n"
            "Подключается к Neo4j, обучается на существующих CAPEC_TO_TECHNIQUE "
            "и добавляет новые рёбра CAPEC_TO_TECHNIQUE_PRED для CAPEC, у которых "
            "не было исходных связей."
        )
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=None,
        help="Количество эпох обучения (по умолчанию GNN_EPOCHS или 60).",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=None,
        help="Максимальное число техник на один CAPEC (по умолчанию 2).",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Минимальный score для записи ребра (по умолчанию 0.5).",
    )
    parser.add_argument(
        "--sentence-model",
        type=str,
        default=None,
        help=(
            "Модель sentence-transformers для эмбеддингов "
            "(по умолчанию sentence-transformers/all-mpnet-base-v2)."
        ),
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Устройство для PyTorch (cpu/cuda, по умолчанию автоопределение).",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["mlp", "dot"],
        default=None,
        help="Режим скоринга: mlp (через MLP-предиктор) или dot (через cosine-сходство). По умолчанию dot.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Не записывать рёбра в Neo4j, только обучение и вывод статистики.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Подгружаем переменные окружения из .env
    load_dotenv()

    args = parse_args(argv)
    cfg = GNNConfig.from_env(args)

    print("Конфигурация GNN:")
    print(f"  Neo4j URI: {cfg.neo4j_uri}")
    print(f"  Neo4j DB: {cfg.neo4j_db}")
    print(f"  Sentence model: {cfg.sentence_model_name}")
    print(f"  Epochs: {cfg.epochs}")
    print(f"  Hidden dim: {cfg.hidden_dim}, Out dim: {cfg.out_dim}")
    print(f"  Top-K per CAPEC: {cfg.top_k}, min_score: {cfg.min_score}")
    print(f"  Device: {cfg.device}")
    print(f"  Mode: {cfg.mode}")
    print(f"  Dry-run: {cfg.dry_run}")

    if not cfg.neo4j_uri or not cfg.neo4j_user or not cfg.neo4j_password:
        print(
            "NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD не заданы. "
            "Укажите их в окружении или .env."
        )
        return 1

    set_random_seed(cfg.seed)

    try:
        print(f"Подключение к Neo4j ({cfg.neo4j_uri}, db={cfg.neo4j_db})…")
        graph = Graph(
            cfg.neo4j_uri, auth=(cfg.neo4j_user, cfg.neo4j_password), name=cfg.neo4j_db
        )
    except Exception as e:
        print(f"[CRITICAL] Не удалось подключиться к Neo4j: {e}")
        return 1

    dataset = CapecTechniqueDataset(graph)
    try:
        dataset.load(cfg)
    except Exception as e:
        print(f"[CRITICAL] Ошибка при загрузке данных из Neo4j: {e}")
        return 1

    if not dataset.pos_pairs:
        print("В базе нет исходных рёбер CAPEC_TO_TECHNIQUE — обучение пропущено.")
        save_roc_auc_json(
            cfg,
            status="no_data",
            meta={"pos_total": 0, "pos_test": 0, "neg_test": 0},
            error="В базе нет исходных рёбер CAPEC_TO_TECHNIQUE.",
        )
        return 0

    try:
        encoder, predictor, z = train_gnn(dataset, cfg)
    except Exception as e:
        print(f"[CRITICAL] Ошибка при обучении GNN: {e}")
        save_roc_auc_json(
            cfg,
            status="error",
            meta={"pos_total": len(dataset.pos_pairs), "pos_test": 0, "neg_test": 0},
            error=f"Ошибка при обучении GNN: {e}",
        )
        return 1

    try:
        new_edges = predict_new_edges(dataset, cfg, z, predictor)
    except Exception as e:
        print(f"[CRITICAL] Ошибка при предсказании рёбер: {e}")
        return 1

    try:
        write_predicted_edges_to_neo4j(dataset, cfg, new_edges)
    except Exception as e:
        print(f"[CRITICAL] Ошибка при записи рёбер в Neo4j: {e}")
        return 1

    print("GNN-процесс завершён.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
