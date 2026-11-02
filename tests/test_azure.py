"""Azure wrapper and error translation, with the SDK fully mocked."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ServiceRequestError
from azure.mgmt.network.models import NetworkSecurityGroup

from nsg_automation.azure.auth import _jwt_claims
from nsg_automation.azure.client import AzureNsgClient
from nsg_automation.azure.errors import translate_azure_error
from nsg_automation.models.rule import NsgRule
from nsg_automation.utils import errors as e

from conftest import SUB, make_rule


def http_error(code: str, status: int, message: str = "details") -> HttpResponseError:
    exc = HttpResponseError(message=f"({code}) {message}")
    exc.status_code = status
    return exc


@pytest.mark.parametrize("code, status, expected", [
    ("AuthorizationFailed", 403, e.AuthorizationError),
    ("InvalidAuthenticationToken", 401, e.AuthenticationError),
    ("SubscriptionNotFound", 404, e.SubscriptionNotFoundError),
    ("InvalidSubscriptionId", 400, e.SubscriptionNotFoundError),
    ("ResourceGroupNotFound", 404, e.ResourceGroupNotFoundError),
    ("ResourceNotFound", 404, e.NsgNotFoundError),
    ("TooManyRequests", 429, e.RateLimitedError),
    ("SecurityRuleConflict", 400, e.PriorityConflictError),
    ("SecurityRuleInvalidPortRange", 400, e.AzureOperationError),
    ("InternalServerError", 500, e.AzureOperationError),
])
def test_http_error_mapping(code, status, expected):
    err = translate_azure_error(http_error(code, status), subscription=SUB, resource_group="rg", nsg="nsg")
    assert type(err) is expected
    assert err.message


def test_rule_not_found_mapping():
    exc = http_error("NotFound", 404, "Resource /subscriptions/x/.../securityRules/r1 not found.")
    assert isinstance(translate_azure_error(exc, nsg="nsg", rule="r1"), e.RuleNotFoundError)


def test_credential_error_mapping():
    err = translate_azure_error(ClientAuthenticationError("DefaultAzureCredential failed"))
    assert isinstance(err, e.AuthenticationError) and "az login" in err.hint


def test_network_error_mapping():
    assert isinstance(translate_azure_error(ServiceRequestError("DNS failure")), e.AzureNetworkError)


def test_jwt_claims_decoding_never_needs_signature():
    import base64, json
    payload = base64.urlsafe_b64encode(json.dumps({"upn": "a@b.com"}).encode()).decode().rstrip("=")
    assert _jwt_claims(f"x.{payload}.sig") == {"upn": "a@b.com"}
    assert _jwt_claims("garbage") == {}


# ---------------------------------------------------------------- client
def _client():
    network = MagicMock()
    return AzureNsgClient(credential=object(), subscription_id=SUB, network_client=network,
                          resource_client=MagicMock()), network


def test_create_or_update_rule_calls_sdk():
    client, network = _client()
    rule = make_rule(source=("10.0.0.0/24", "10.0.1.0/24"))
    network.security_rules.begin_create_or_update.return_value.result.return_value = rule.to_azure()
    assert client.create_or_update_rule("rg", "nsg", rule) == rule
    args = network.security_rules.begin_create_or_update.call_args.args
    assert args[:3] == ("rg", "nsg", "Allow-HTTPS")
    assert args[3].source_address_prefixes == ["10.0.0.0/24", "10.0.1.0/24"]
    assert args[3].priority == 100


def test_delete_rule_calls_sdk():
    client, network = _client()
    client.delete_rule("rg", "nsg", "r1")
    network.security_rules.begin_delete.assert_called_once_with("rg", "nsg", "r1")


def test_list_rules_converts_models():
    client, network = _client()
    network.network_security_groups.get.return_value = SimpleNamespace(
        security_rules=[make_rule().to_azure()], default_security_rules=[])
    assert client.list_rules("rg", "nsg") == [make_rule()]


def test_replace_rules_does_single_put_preserving_nsg_properties():
    client, network = _client()
    existing = NetworkSecurityGroup(location="eastus", tags={"env": "prod"},
                                    security_rules=[make_rule("Old").to_azure()])
    network.network_security_groups.get.return_value = existing
    network.network_security_groups.begin_create_or_update.return_value.result.return_value = existing
    result = client.replace_rules("rg", "nsg", [make_rule("New")])
    sent = network.network_security_groups.begin_create_or_update.call_args.args[2]
    assert sent.location == "eastus" and sent.tags == {"env": "prod"}
    assert [r.name for r in sent.security_rules] == ["New"]
    assert [r.name for r in result] == ["New"]
    network.security_rules.begin_create_or_update.assert_not_called()


def test_sdk_errors_are_translated():
    client, network = _client()
    network.network_security_groups.get.side_effect = http_error("ResourceGroupNotFound", 404)
    with pytest.raises(e.ResourceGroupNotFoundError):
        client.list_rules("missing-rg", "nsg")


def test_nsg_exists():
    client, network = _client()
    network.network_security_groups.get.side_effect = http_error("ResourceNotFound", 404)
    assert client.nsg_exists("rg", "nsg") is False


def test_resource_id():
    client, _ = _client()
    assert client.rule_resource_id("rg", "nsg", "r").endswith(
        "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg/securityRules/r")
