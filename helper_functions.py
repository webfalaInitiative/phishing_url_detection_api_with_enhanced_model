import numpy as np
from urllib.parse import urlparse

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text (high entropy often indicates randomness)"""
    if not text:
        return 0
    text = text.lower()
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0
    for count in freq.values():
        prob = count / len(text)
        entropy -= prob * np.log2(prob)
    return entropy
