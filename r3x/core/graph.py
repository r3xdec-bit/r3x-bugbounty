"""
R3X Intelligent Attack Surface Graph
Visualizes target topology, subdomains, endpoints, tech stacks, and vulnerabilities using NetworkX & Rich.
"""
import networkx as nx
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from r3x.memory.db import db

console = Console()

class AttackSurfaceGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_project(self, project_id_or_name: str = "default") -> nx.DiGraph:
        """Constructs graph topology from SQLite project memory."""
        self.graph.clear()
        proj = db.get_project(project_id_or_name)
        if not proj:
            return self.graph

        p_id = proj["id"]
        p_name = proj["name"]
        self.graph.add_node(f"PROJ:{p_name}", type="PROJECT", label=p_name)

        # Targets
        targets = db.get_targets(p_id)
        for t in targets:
            t_node = f"TARGET:{t['hostname']}"
            self.graph.add_node(t_node, type="HOST", label=t["hostname"], url=t["url"])
            self.graph.add_edge(f"PROJ:{p_name}", t_node, relation="HAS_TARGET")

        # Findings
        findings = db.list_findings(project_id=p_id)
        for f in findings:
            ep = f.get("endpoint", "")
            ep_node = f"ENDPOINT:{ep}"
            self.graph.add_node(ep_node, type="ENDPOINT", label=ep)

            # Connect host to endpoint
            host_match = None
            for t in targets:
                if t["hostname"] in ep:
                    host_match = f"TARGET:{t['hostname']}"
                    break
            if host_match:
                self.graph.add_edge(host_match, ep_node, relation="EXPOSES")
            else:
                self.graph.add_edge(f"PROJ:{p_name}", ep_node, relation="EXPOSES")

            f_node = f"FINDING:{f['id']}"
            self.graph.add_node(
                f_node,
                type="FINDING",
                label=f["title"],
                severity=f["severity"],
                cvss=f.get("cvss", 0.0),
                status=f["status"]
            )
            self.graph.add_edge(ep_node, f_node, relation="HAS_VULNERABILITY")

        return self.graph

    def get_tree(self, project_id_or_name: str = "default") -> Tree:
        """Build and return the hierarchical Rich Tree representation of the attack surface graph."""
        g = self.build_from_project(project_id_or_name)
        proj = db.get_project(project_id_or_name) or {"name": project_id_or_name}

        root_tree = Tree(f"[bold cyan]🌐 Attack Surface Graph: {proj['name']}[/]")
        host_nodes = [n for n, d in g.nodes(data=True) if d.get("type") == "HOST"]
        for h in host_nodes:
            h_data = g.nodes[h]
            h_branch = root_tree.add(f"[bold white]🖥 Host:[/] [cyan]{h_data['label']}[/]")

            endpoints = [v for u, v, d in g.out_edges(h, data=True) if d.get("relation") == "EXPOSES"]
            for ep in endpoints:
                ep_data = g.nodes[ep]
                ep_branch = h_branch.add(f"[bold green]🔗 Endpoint:[/] [dim]{ep_data['label']}[/]")

                vulnerabilities = [v for u, v, d in g.out_edges(ep, data=True) if d.get("relation") == "HAS_VULNERABILITY"]
                for v in vulnerabilities:
                    v_data = g.nodes[v]
                    sev = v_data["severity"].upper()
                    sev_color = "red" if sev in ["CRITICAL", "HIGH"] else ("yellow" if sev == "MEDIUM" else "blue")
                    ep_branch.add(
                        f"[{sev_color}]⚡ [{sev}][/] {v_data['label']} "
                        f"[dim](CVSS: {v_data.get('cvss')}) - {v_data.get('status')}[/]"
                    )
        return root_tree

    def render_terminal(self, project_id_or_name: str = "default") -> None:
        """Renders the attack surface graph as a structured hierarchical Rich terminal tree."""
        g = self.build_from_project(project_id_or_name)
        if len(g.nodes) <= 1:
            console.print("[yellow]Attack surface graph is empty. Run a scan to discover assets.[/]")
            return

        root_tree = self.get_tree(project_id_or_name)
        console.print(Panel(root_tree, title="[bold cyan]R3X Neural Topology & Vulnerability Graph[/]"))
        console.print(f"[dim]Total Nodes: {len(g.nodes)} | Total Edges: {len(g.edges)}[/]\n")

surface_graph = AttackSurfaceGraph()
