"""
PE-Sentinel: Advanced Behavioral Analysis Engine
Complements section-level analysis with capability clustering and correlation.
"""

from .extractors import FeatureExtractor
from .correlators import FunctionalClusterer, CorrelationEngine
from .verdict_engine import VerdictEngine, IndiscrepancyFilter

__all__ = [
    "FeatureExtractor",
    "FunctionalClusterer",
    "CorrelationEngine",
    "VerdictEngine",
    "IndiscrepancyFilter",
]
