SYN = 0x02
ACK = 0x10


def is_syn_only(flags) -> bool:
    """SYN set, ACK clear. Ignores ECE/CWR/URG/PSH etc."""
    return flags is not None and (flags & (SYN | ACK)) == SYN
