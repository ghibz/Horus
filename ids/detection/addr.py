# Addressing for IPv4/6 to tell whether it's port of IPv6
def format_endpoint(ip, port):
    """'10.0.0.1:80' for IPv4, '[2001:db8::1]:80' for IPv6."""
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"