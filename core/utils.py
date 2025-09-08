import re

def normalize_zapret_string(s: str) -> str:
    """
    Normalize zapret strategy strings by fixing invalid parameters.
    
    - multisplit with split-count < 3 is meaningless, convert to fakedisorder
    - TTL should be in reasonable TCP range (2-10)
    """
    # multisplit with split-count < 3 is meaningless
    if "--dpi-desync=multisplit" in s and re.search(r"--dpi-desync-split-count=([0-2])", s):
        return re.sub(r"--dpi-desync=multisplit.*", "--dpi-desync=fakedisorder --dpi-desync-split-pos=3", s)
    
    # TTL in reasonable TCP limits
    s = re.sub(
        r"--dpi-desync-ttl=(\d+)", 
        lambda m: f"--dpi-desync-ttl={min(10, max(2, int(m.group(1))))}", 
        s
    )
    
    return s