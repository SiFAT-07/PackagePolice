def evaluate(name: str) -> float:
    """Heuristic: many non-alphabetic characters increase suspicion."""
    import re
    non_alpha = len([c for c in name if not c.isalpha()])
    ratio = non_alpha / max(1, len(name))
    if ratio > 0.5:
        return 0.9
    if ratio > 0.2:
        return 0.5
    return 0.0
