def evaluate(name: str) -> float:
    """Simple heuristic: suspicious keywords raise the score."""
    bad_keywords = ["malware","exploit","rce","payload","backdoor","trojan","virus","script"]
    n = name.lower()
    for k in bad_keywords:
        if k in n:
            return 1.0
    return 0.0
