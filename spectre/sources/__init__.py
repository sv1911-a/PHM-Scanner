"""Source adapters for SPECTRE intelligence collection.

Plugins should prefer using adapters instead of directly calling external
services. This keeps collection mechanics, caching, authentication, and provider
quirks outside the plugin lifecycle.
"""
