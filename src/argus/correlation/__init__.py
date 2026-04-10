"""Correlation Engine — chains findings into compound attack paths.

The Correlation Engine runs after all attack agents complete. It looks at
the collected findings and identifies cases where two or more findings,
when combined, represent a higher-impact exploit than either does alone.

This is the v1 implementation: rule-based correlation over finding clusters
grouped by target host, attack class signals, and OWASP category. v2 will
add LLM-driven path synthesis and replay-based validation.
"""

from argus.correlation.engine import CorrelationEngine

__all__ = ["CorrelationEngine"]
