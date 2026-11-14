"""[3] Task Graph builder: converts Requirement DAG into ordered worker LeafTasks without oracle leakage."""

from __future__ import annotations

from hveritas.spec.models import CompiledSpec, LeafTask, TaskBudget


def build_task_graph(
    spec: CompiledSpec, default_budget: TaskBudget | None = None
) -> list[LeafTask]:
    """Produce topologically ordered LeafTasks containing ONLY visible proxy checks (I4)."""
    budget = default_budget or TaskBudget()
    node_map = {n.id: n for n in spec.nodes}
    tasks: list[LeafTask] = []

    for req_id in spec.topological_order:
        node = node_map[req_id]
        proxy_code = node.proxy_oracle.custom_pytest_code or ""
        tasks.append(
            LeafTask(
                task_id=f"task_{node.id}",
                requirement_id=node.id,
                statement=node.statement,
                target_file=node.target_file,
                function_name=node.function_name,
                arg_names=node.arg_names,
                depends_on_tasks=[f"task_{dep}" for dep in node.depends_on],
                visible_proxy_tests={f"test_proxy_{node.id}.py": proxy_code},
                api_contract={
                    "file": node.target_file,
                    "functions": {node.function_name: node.arg_names},
                },
                budget=budget,
            )
        )
    return tasks
