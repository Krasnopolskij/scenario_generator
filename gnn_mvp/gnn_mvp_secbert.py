import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import roc_auc_score  # Добавлено для ROC-AUC
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.utils import negative_sampling
import random  # Добавлено для negative sampling
import networkx as nx  # Добавлено для визуализации
import matplotlib.pyplot as plt  # Добавлено для визуализации
from transformers import BertTokenizer, BertModel
from tqdm import tqdm
import numpy as np 
from secbert_ui import visualize_graph  # Импортируем функцию визуализации
from pathlib import Path

# =========================
# 1. Загружаем CSV (относительные пути от директории файла)
# =========================
BASE = Path(__file__).parent.resolve()
nodes = pd.read_csv(BASE / "nodes.csv")
edges = pd.read_csv(BASE / "edges.csv")

# Чистим кавычки и пробелы
for col in ["id", "label", "name", "description"]:
    if col in nodes.columns:
        nodes[col] = nodes[col].astype(str).str.strip().str.strip('"')

for col in ["source", "target", "relation"]:
    if col in edges.columns:
        edges[col] = edges[col].astype(str).str.strip().str.strip('"')

print("=== NODES SAMPLE ===")
print(nodes.head())
print(nodes['label'].value_counts())

print("\n=== EDGES SAMPLE ===")
print(edges.head())
print(edges['relation'].value_counts())

# Проверка на NaN после маппинга (новое)
if edges['source'].isna().any() or edges['target'].isna().any():
    print("Ошибка: некоторые source или target не найдены")
    print(edges[edges['source'].isna() | edges['target'].isna()])
    exit(1)

# =========================
# 2. Кодируем тип узлов
# =========================
label_encoder = LabelEncoder()
nodes['label_id'] = label_encoder.fit_transform(nodes['label'])
num_classes = len(label_encoder.classes_)

x = torch.nn.functional.one_hot(
    torch.tensor(nodes['label_id'].values), num_classes=num_classes
).to(torch.float)

# Добавляем BERT-эмбеддинги из description (новое)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
tokenizer = BertTokenizer.from_pretrained("markusbayer/CySecBERT")
bert_model = BertModel.from_pretrained("markusbayer/CySecBERT").to(device)
bert_model.eval()

def get_cysecbert_embeddings(texts, batch_size=16):
    embeddings = []
    for i in tqdm(range(0, len(texts), batch_size), desc="Encoding descriptions"):
        batch_texts = texts[i:i + batch_size]
        inputs = tokenizer(batch_texts.tolist(), return_tensors="pt", padding=True, truncation=True, max_length=512)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = bert_model(**inputs)
        embeddings.append(outputs.last_hidden_state[:, 0, :].cpu())  # [CLS] token
    return torch.cat(embeddings, dim=0)

descriptions = nodes['description'].fillna('')
bert_emb = get_cysecbert_embeddings(descriptions)
x = torch.cat([x, bert_emb], dim=1)  # One-hot + 768-dim CySecBERT

id_map = {eid: i for i, eid in enumerate(nodes['id'])}

# =========================
# 3. Рёбра
# =========================
edges['source'] = edges['source'].map(id_map)
edges['target'] = edges['target'].map(id_map)

edge_index = torch.tensor(
    [edges['source'].values, edges['target'].values], dtype=torch.long
)

print(f"\nGraph has {nodes.shape[0]} nodes and {edges.shape[0]} edges")

# Train/test split (новое)
num_edges = edge_index.shape[1]
perm = torch.randperm(num_edges)
train_mask = perm[:int(0.8 * num_edges)]
test_mask = perm[int(0.8 * num_edges):]
train_edge_index = edge_index[:, train_mask]
test_edge_index = edge_index[:, test_mask]

# Type-aware negative sampling (новое)
capec_idxs = nodes[nodes['label'] == "CAPEC"].index.values
tech_idxs = nodes[nodes['label'] == "Technique"].index.values
all_possible = [(c, t) for c in capec_idxs for t in tech_idxs]
existing = set(zip(edges['source'], edges['target']))
neg_candidates = [(c, t) for c, t in all_possible if (c, t) not in existing]
neg_edge_index = torch.tensor(random.sample(neg_candidates, num_edges), dtype=torch.long).t()
train_neg = neg_edge_index[:, :int(0.8 * num_edges)]
test_neg = neg_edge_index[:, int(0.8 * num_edges):]

# =========================
# 4. Модель GCN
# =========================
class GCN(nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, out_channels)
        self.dropout = nn.Dropout(0.5)  # Добавлено для регуляризации

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)  # Добавлено
        x = self.conv2(x, edge_index)
        return x

# =========================
# 5. Обучение
# =========================
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

model = GCN(in_channels=x.size(1), hidden_channels=32, out_channels=32).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)  # Добавлено L2

x, train_edge_index, test_edge_index = x.to(device), train_edge_index.to(device), test_edge_index.to(device)
train_neg = train_neg.to(device)
test_neg = test_neg.to(device)

def get_score(z, edge_index):
    z = F.normalize(z, p=2, dim=1)
    return (z[edge_index[0]] * z[edge_index[1]]).sum(dim=1)

eps = 1e-15

for epoch in tqdm(range(201), desc="Training"):
    model.train()
    optimizer.zero_grad()
    z = model(x, train_edge_index)  # Используем train_edge_index
    pos_score = get_score(z, train_edge_index)
    neg_score = get_score(z, train_neg)
    pos_loss = -torch.log(torch.sigmoid(pos_score).clamp(min=eps, max=1-eps)).mean()
    neg_loss = -torch.log((1 - torch.sigmoid(neg_score)).clamp(min=eps, max=1-eps)).mean()
    loss = pos_loss + neg_loss
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"Epoch {epoch}, Loss {loss.item():.4f}, pos_loss={pos_loss.item():.4f}, neg_loss={neg_loss.item():.4f}")

# =========================
# 6. Оценка качества (новое)
# =========================
model.eval()
with torch.no_grad():
    z = model(x, train_edge_index)
    pos_score = get_score(z, test_edge_index).cpu().numpy()
    neg_score = get_score(z, test_neg).cpu().numpy()
    scores = np.concatenate([pos_score, neg_score])
    labels = np.concatenate([np.ones(len(pos_score)), np.zeros(len(neg_score))])
    auc = roc_auc_score(labels, scores)
    print(f"\nTest ROC-AUC: {auc:.4f}")

# =========================
# 7. Предсказание новых связей
# =========================
candidate_edges = torch.tensor(neg_candidates, dtype=torch.long).t().to(device)  # Векторизация
with torch.no_grad():
    scores = get_score(z, candidate_edges).cpu().numpy()
scores = [(i, j, s) for (i, j), s in zip(neg_candidates, scores) if (i, j) not in existing]
scores = sorted(scores, key=lambda x: -x[2])

print("\nTop-20 predicted NEW CAPEC→Technique links:")
for i, j, s in scores[:20]:  # Топ 20 самых вероятных
    print(f"{nodes.iloc[i]['name']} → {nodes.iloc[j]['name']} | score={s:.4f}")

# =========================
# 8. Сохраняем только новые предсказанные рёбра для Gephi
# =========================

# Маппинг индекса к id
idx_to_id = dict(enumerate(nodes['id'].values))
existing_ids = set(nodes['id'].values)

predicted_edges = []
for i, j, s in scores[:100]:  # или все: scores
    src_id = idx_to_id.get(i)
    tgt_id = idx_to_id.get(j)
    # Добавляем только если оба id реально существуют среди узлов
    if src_id in existing_ids and tgt_id in existing_ids:
        predicted_edges.append({
            'source': f'"{src_id}"',
            'target': f'"{tgt_id}"',
            'relation': 'CAPEC_TO_TECHNIQUE',
            'score': s,
            'is_predicted': 1
        })

predicted_edges_df = pd.DataFrame(predicted_edges)
predicted_edges_df.to_csv(str(BASE / "predicted_edges.csv"), index=False)
print("Файл с новыми рёбрами для Gephi сохранён: predicted_edges.csv")
