"""
Shared utility functions
"""

import os


def format_bytes(size: int) -> str:
    """Format bytes to human-readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_hex(value: int) -> str:
    """Format integer as hex string"""
    return f"0x{value:x}"
