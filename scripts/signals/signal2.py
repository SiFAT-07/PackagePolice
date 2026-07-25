def evaluate(name: str) -> float:
    """Heuristic: extremely short or very long package names are suspicious."""
    l = len(name)
    if l <= 1:
        return 1.0
    if l <= 3:
        return 0.6
    if l > 40:
        return 0.8
    return 0.0
