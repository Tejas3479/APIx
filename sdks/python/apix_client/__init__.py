"""Official Python client for APIx — Real-Time Airfare Price Index & Analytics Engine."""

from .client import APIxClient, APIxError, AsyncAPIxClient

__all__ = ["APIxClient", "APIxError", "AsyncAPIxClient"]
__version__ = "1.0.0"
