def evaluate(name: str) -> float:
    """Placeholder for reputation checks — deterministic stub here.

    Returns 0.0 for known-safe patterns (e.g., names with 'py' or 'js'), else 0.3.
    """
    n = name.lower()
    if n.startswith("py") or n.endswith("py") or n.endswith("js"):
        return 0.0
    return 0.3
