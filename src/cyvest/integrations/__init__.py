"""
Bridges to agent frameworks.

Each subpackage imports its framework lazily and raises a clear ``ImportError`` pointing at the
matching extra, so the core of cyvest never depends on any of them.
"""
