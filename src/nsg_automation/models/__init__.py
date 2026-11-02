"""Domain models (Azure-SDK independent)."""

from nsg_automation.models.config import NsgConfig
from nsg_automation.models.rule import ALLOW, ANY, DENY, INBOUND, OUTBOUND, NsgRule

__all__ = ["NsgRule", "NsgConfig", "INBOUND", "OUTBOUND", "ALLOW", "DENY", "ANY"]
