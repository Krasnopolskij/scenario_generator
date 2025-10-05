import pandas as pd
import torch
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('TkAgg')  # или 'Qt5Agg', 'GTK3Agg'


def visualize_graph(nodes_path, edges_path, top_predicted_links, show_real=True, show_predicted=True):
    """
    Визуализирует граф CAPEC→Technique с настоящими и/или предсказанными связями.
    :param nodes_path: путь к nodes.csv
    :param edges_path: путь к edges.csv
    :param top_predicted_links: список [(i, j, score)], где i, j — индексы узлов, score — уверенность
    :param show_real: показывать настоящие связи (синие)
    :param show_predicted: показывать предсказанные связи (красные)
    """
    # Загрузка данных
    nodes = pd.read_csv(nodes_path)
    edges = pd.read_csv(edges_path)

    # Чистим кавычки и пробелы
    for col in ["id", "label", "name", "description"]:
        if col in nodes.columns:
            nodes[col] = nodes[col].astype(str).str.strip().str.strip('"')
    for col in ["source", "target", "relation"]:
        if col in edges.columns:
            edges[col] = edges[col].astype(str).str.strip().str.strip('"')

    id_map = {eid: i for i, eid in enumerate(nodes['id'])}

    # Создаём граф
    G = nx.DiGraph()
    for idx, row in nodes.iterrows():
        G.add_node(idx, label=row['label'], name=row['name'])

    # Добавляем настоящие рёбра CAPEC→Technique
    if show_real:
        for _, row in edges.iterrows():
            src = id_map.get(row['source'])
            tgt = id_map.get(row['target'])
            if src is not None and tgt is not None:
                if nodes.iloc[src]['label'] == "CAPEC" and nodes.iloc[tgt]['label'] == "Technique":
                    G.add_edge(src, tgt, color='blue', style='solid', real=True)

    # Добавляем предсказанные рёбра
    if show_predicted:
        for i, j, score in top_predicted_links:
            G.add_edge(i, j, color='red', style='dashed', real=False, score=score)

    # Визуализация
    pos = nx.spring_layout(G, seed=42)
    plt.figure(figsize=(14, 10))

    # Узлы: CAPEC — оранжевые, Technique — зелёные, остальные — серые
    node_colors = []
    for idx in G.nodes:
        label = G.nodes[idx]['label']
        if label == "CAPEC":
            node_colors.append('orange')
        elif label == "Technique":
            node_colors.append('green')
        else:
            node_colors.append('lightgray')

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=400)
    nx.draw_networkx_labels(G, pos, labels={idx: G.nodes[idx]['name'] for idx in G.nodes}, font_size=8)

    # Рёбра: настоящие — синие, предсказанные — красные пунктирные
    solid_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('real', False)]
    dashed_edges = [(u, v) for u, v, d in G.edges(data=True) if not d.get('real', False)]

    if show_real:
        nx.draw_networkx_edges(G, pos, edgelist=solid_edges, edge_color='blue', arrows=True)
    if show_predicted:
        nx.draw_networkx_edges(G, pos, edgelist=dashed_edges, edge_color='red', style='dashed', arrows=True)
        # Подписи для предсказанных рёбер (score)
        edge_labels = {(i, j): f"{G.edges[i, j]['score']:.2f}" for i, j in dashed_edges}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='red', font_size=8)

    plt.title("CAPEC→Technique: настоящие (синие) и предсказанные (красные пунктирные) связи")
    plt.axis('off')
    plt.tight_layout()
    plt.show()


def visualize_graphs_both_modes(nodes_path, edges_path, top_predicted_links):
    # Окно 1: настоящие + предсказанные
    visualize_graph(nodes_path, edges_path, top_predicted_links, show_real=True, show_predicted=True)
    # Окно 2: только предсказанные
    visualize_graph(nodes_path, edges_path, top_predicted_links, show_real=False, show_predicted=True)