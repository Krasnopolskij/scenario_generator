# =========================
# gnn_mvp_fixed.py
# =========================

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import LabelEncoder
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.utils import negative_sampling
from tqdm import tqdm
from sklearn.metrics.pairwise import cosine_similarity

# =========================
# 1. Загружаем CSV
# =========================
nodes = pd.read_csv("/home/s1r1us/GenScenario/gnn_mvp/nodes.csv")
edges = pd.read_csv("/home/s1r1us/GenScenario/gnn_mvp/edges.csv")

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

# =========================
# 2. Кодируем тип узлов
# =========================
label_encoder = LabelEncoder()
nodes['label_id'] = label_encoder.fit_transform(nodes['label'])
num_classes = len(label_encoder.classes_)

x = torch.nn.functional.one_hot(
    torch.tensor(nodes['label_id'].values), num_classes=num_classes
).to(torch.float)

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

# =========================
# 4. Модель GCN
# =========================
class GCN(nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        return x

# =========================
# 5. Обучение
# =========================
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

model = GCN(in_channels=x.size(1), hidden_channels=32, out_channels=32).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=0.005)

x, edge_index = x.to(device), edge_index.to(device)

pos_edge_index = edge_index
neg_edge_index = negative_sampling(
    edge_index, num_nodes=x.size(0), num_neg_samples=pos_edge_index.size(1)
)

def get_score(z, edge_index):
    # Нормализация эмбеддингов для стабильности
    z = F.normalize(z, p=2, dim=1)
    return (z[edge_index[0]] * z[edge_index[1]]).sum(dim=1)

eps = 1e-15

for epoch in range(201):
    model.train()
    optimizer.zero_grad()
    z = model(x, edge_index)

    pos_score = get_score(z, pos_edge_index)
    neg_score = get_score(z, neg_edge_index)

    pos_loss = -torch.log(torch.sigmoid(pos_score).clamp(min=eps, max=1-eps)).mean()
    neg_loss = -torch.log((1 - torch.sigmoid(neg_score)).clamp(min=eps, max=1-eps)).mean()
    loss = pos_loss + neg_loss

    loss.backward()
    optimizer.step()

    if epoch % 10 == 0:
        print(f"Epoch {epoch}, Loss {loss.item():.4f}, pos_loss={pos_loss.item():.4f}, neg_loss={neg_loss.item():.4f}")

# =========================
# 6. Предсказание новых связей
# =========================
model.eval()
z = model(x, edge_index)

capec_nodes = nodes[nodes['label'] == "CAPEC"].index
tech_nodes = nodes[nodes['label'] == "Technique"].index

print(f"\nFound {len(capec_nodes)} CAPEC nodes and {len(tech_nodes)} Technique nodes")

candidates = [(i, j) for i in capec_nodes for j in tech_nodes]

scores = [
    (i, j, get_score(z, torch.tensor([[i],[j]], device=device)).item())
    for i, j in candidates
]

# Убираем уже существующие связи
existing = set(zip(edges['source'], edges['target']))
scores = [(i, j, s) for i, j, s in scores if (i, j) not in existing]

scores = sorted(scores, key=lambda x: -x[2])

print("\nTop-10 predicted NEW CAPEC→Technique links:")
for i, j, s in scores[:100]:
    print(f"{nodes.iloc[i]['name']} → {nodes.iloc[j]['name']} | score={s:.4f}")
