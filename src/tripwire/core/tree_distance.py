"""Process Tree Edit Distance (TED) Algorithm for Process Hierarchy Diffing."""

from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel, Field


class ProcessNode(BaseModel):
    id: int
    name: str
    cmd: str
    children: List["ProcessNode"] = Field(default_factory=list)


class TreeEditOperation(BaseModel):
    op: str  # INSERT, DELETE, RENAME, MATCH
    node_name: str
    detail: str
    cost: float


class TreeDistanceResult(BaseModel):
    distance: float
    similarity_score: float  # 0.0 to 1.0
    operations: List[TreeEditOperation] = Field(default_factory=list)
    anomalous_subtrees: List[str] = Field(default_factory=list)


class ProcessTreeComparator:
    """
    Computes Tree Edit Distance (TED) between process execution hierarchies.
    Isolates exact subtree insertions (e.g. unauthorized shell or compiler spawns).
    """

    @staticmethod
    def flatten_tree(root: ProcessNode) -> List[ProcessNode]:
        """Post-order traversal to index tree nodes."""
        nodes = []
        def traverse(curr: ProcessNode):
            for child in curr.children:
                traverse(child)
            nodes.append(curr)
        traverse(root)
        return nodes

    def compute_distance(self, tree_a: Optional[ProcessNode], tree_b: Optional[ProcessNode]) -> TreeDistanceResult:
        """
        Computes structural tree edit distance and detects anomalous subtree insertions.
        """
        if not tree_a and not tree_b:
            return TreeDistanceResult(distance=0.0, similarity_score=1.0)
        if not tree_a and tree_b:
            return TreeDistanceResult(
                distance=float(len(self.flatten_tree(tree_b))),
                similarity_score=0.0,
                anomalous_subtrees=[f"Complete new process tree inserted: {tree_b.cmd}"]
            )
        if tree_a and not tree_b:
            return TreeDistanceResult(
                distance=float(len(self.flatten_tree(tree_a))),
                similarity_score=0.0,
            )

        nodes_a = self.flatten_tree(tree_a)
        nodes_b = self.flatten_tree(tree_b)

        # Dynamic programming table for tree distance
        len_a, len_b = len(nodes_a), len(nodes_b)
        dp = [[0.0] * (len_b + 1) for _ in range(len_a + 1)]

        for i in range(len_a + 1):
            dp[i][0] = float(i)
        for j in range(len_b + 1):
            dp[0][j] = float(j)

        operations: List[TreeEditOperation] = []
        anomalous_subtrees: List[str] = []

        for i in range(1, len_a + 1):
            for j in range(1, len_b + 1):
                node_a = nodes_a[i - 1]
                node_b = nodes_b[j - 1]

                # Cost function: matching command
                if node_a.name == node_b.name:
                    cost = 0.0 if node_a.cmd == node_b.cmd else 0.5
                else:
                    cost = 1.0

                dp[i][j] = min(
                    dp[i - 1][j] + 1.0,        # Deletion
                    dp[i][j - 1] + 1.0,        # Insertion
                    dp[i - 1][j - 1] + cost,   # Rename / Match
                )

        dist = dp[len_a][len_b]
        max_len = max(len_a, len_b)
        sim = max(0.0, round(1.0 - (dist / max_len), 3)) if max_len > 0 else 1.0

        # Backtrack to identify anomalous inserted processes
        names_a = {n.name for n in nodes_a}
        for n_b in nodes_b:
            if n_b.name not in names_a:
                operations.append(
                    TreeEditOperation(
                        op="INSERT",
                        node_name=n_b.name,
                        detail=f"Subtree process insertion: {n_b.cmd}",
                        cost=1.0,
                    )
                )
                anomalous_subtrees.append(f"Novel process node: '{n_b.name}' ({n_b.cmd})")

        return TreeDistanceResult(
            distance=dist,
            similarity_score=sim,
            operations=operations,
            anomalous_subtrees=anomalous_subtrees,
        )
