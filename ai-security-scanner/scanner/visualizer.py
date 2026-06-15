import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

def generate_flow_graph(scan_results, output_path="reports/flow_graph.png"):
    """
    Generates a pipeline/code flow graph showing
    safe vs risky nodes and saves it as an image.
    """
    os.makedirs("reports", exist_ok=True)

    G = nx.DiGraph()

    node_colors = []
    node_labels = {}

    for i, result in enumerate(scan_results):
        filename = os.path.basename(result.get("filepath", f"file_{i}"))
        risk     = result.get("risk_level", "LOW")
        score    = result.get("score", 0)

        node_id  = f"node_{i}"
        label    = f"{filename}\n{risk} ({score}/100)"

        G.add_node(node_id)
        node_labels[node_id] = label

        if risk == "HIGH":
            node_colors.append("#ef4444")
        elif risk == "MEDIUM":
            node_colors.append("#f59e0b")
        else:
            node_colors.append("#22c55e")

        # Connect nodes sequentially (pipeline flow)
        if i > 0:
            prev = f"node_{i-1}"
            G.add_edge(prev, node_id)

    # Draw graph
    plt.figure(figsize=(12, 6))
    plt.style.use("dark_background")

    pos = nx.spring_layout(G, seed=42)

    nx.draw_networkx_nodes(G, pos,
        node_color=node_colors,
        node_size=3000,
        alpha=0.9)

    nx.draw_networkx_labels(G, pos,
        labels=node_labels,
        font_size=8,
        font_color="white")

    nx.draw_networkx_edges(G, pos,
        edge_color="#aaaaaa",
        arrows=True,
        arrowsize=20,
        width=2)

    # Legend
    patches = [
        mpatches.Patch(color="#ef4444", label="HIGH Risk"),
        mpatches.Patch(color="#f59e0b", label="MEDIUM Risk"),
        mpatches.Patch(color="#22c55e", label="LOW Risk"),
    ]
    plt.legend(handles=patches, loc="upper left",
               facecolor="#1a1d2e", labelcolor="white")

    plt.title("🛡️ AI Security Scanner — Flow Graph",
              color="white", fontsize=14, pad=20)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150,
                bbox_inches="tight", facecolor="#0f1117")
    plt.close()

    print(f"📊 Flow graph saved to: {output_path}")
    return output_path