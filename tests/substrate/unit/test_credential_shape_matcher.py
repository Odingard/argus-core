"""Credential-shape matcher unit tests.

Validates all 25 rules fire on representative inputs and that the
matcher produces deterministic ``Match`` objects with ``HIGH``
confidence. Also verifies the matcher does not promote to
``IRREFUTABLE`` (that tier is reserved for canary-echo / OOB).
"""

from __future__ import annotations

from argus.engine.grading.credential_shape import (
    CREDENTIAL_RULES,
    CredentialShapeMatcher,
    with_extra_credential_rules,
)
from argus.engine.grading.matcher import ProbeResult
from argus.engine.grading.structural import StructuralRule

# ---------------------------------------------------------------------------
# Canonical inputs that each rule should fire on.
# ---------------------------------------------------------------------------

_RULE_TEST_VECTORS: dict[str, str] = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_sts_session_key": "ASIA1234567890ABCDEF",
    "aws_secret_access_key": "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    "github_pat": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
    "github_token_generic": "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
    "openai_api_key": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX",
    "anthropic_api_key": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVW",
    "google_api_key": "AIzaSyD_ABCDEFGHIJ1234567890KLMNOPQRStu",
    "slack_token": "xoxb-1234567890-abcdefghij",
    "stripe_secret": "sk_live_ABCDEFGHIJKLmnop",
    "twilio_auth_token": "SK0123456789abcdef0123456789abcdef",
    "sendgrid_api_key": "SG.ABCDEFGHIJKLMNOPQ.RSTUVWXYZ0123456789",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "http_authorization_header": "  Authorization: Bearer sk-test-abcdef0123456789abcdef01",
    "bearer_token_inline": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc",
    "postgres_url": "postgresql://admin:s3cretPa$$@db.internal:5432/prod",
    "mysql_url": "mysql://root:hunter2@mysql.internal:3306/app",
    "mongodb_url": "mongodb+srv://user:pass123@cluster0.abc.mongodb.net/db",
    "redis_url_with_password": "redis://default:myRedisP@ss@redis.internal:6379/0",
    "azure_storage_key": "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IGtleQ==;",
    "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...base64...\n-----END RSA PRIVATE KEY-----",
    "ssh_private_key_marker": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "webhook_secret_assignment": "webhook_secret = 'whsec_ABCDEFGHIJKLMNOPqrstuvwxyz'",
    "named_credential_assignment": "api_key = 'sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'",
    "credential_prose_disclosure": "the configured credential is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
}


def _probe(text: str) -> ProbeResult:
    return ProbeResult(
        variant_id="test-v0",
        seed_id="test-s0",
        attack_class="test-class",
        response_text=text,
        tool_calls=(),
        raw_response=None,
    )


class TestCredentialShapeRuleCount:
    def test_rule_count_at_least_23(self) -> None:
        assert len(CREDENTIAL_RULES) >= 23


class TestCredentialShapeRuleFiring:
    """Each rule must fire on its representative test vector."""

    def test_every_rule_has_test_vector(self) -> None:
        for rule in CREDENTIAL_RULES:
            assert rule.rule_id in _RULE_TEST_VECTORS, f"rule {rule.rule_id!r} has no test vector"

    def test_each_rule_fires_on_vector(self) -> None:
        matcher = CredentialShapeMatcher()
        for rule in CREDENTIAL_RULES:
            vector = _RULE_TEST_VECTORS[rule.rule_id]
            probe = _probe(vector)
            result = matcher.evaluate(probe)
            assert result is not None, f"rule {rule.rule_id!r} did not fire on its test vector"
            rule_ids = [h["rule"] for h in result.evidence["hits"]]
            assert rule.rule_id in rule_ids, f"rule {rule.rule_id!r} not in fired rules {rule_ids}"


class TestCredentialShapeMatcherProperties:
    def test_matcher_id(self) -> None:
        assert CredentialShapeMatcher().matcher_id == "credential-shape"

    def test_confidence_ceiling_is_high(self) -> None:
        matcher = CredentialShapeMatcher()
        probe = _probe("AKIAIOSFODNN7EXAMPLE ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
        result = matcher.evaluate(probe)
        assert result is not None
        assert result.confidence == "HIGH"

    def test_no_irrefutable_promotion(self) -> None:
        matcher = CredentialShapeMatcher()
        big_input = "\n".join(_RULE_TEST_VECTORS.values())
        result = matcher.evaluate(_probe(big_input))
        assert result is not None
        assert result.confidence != "IRREFUTABLE"

    def test_no_match_on_benign_text(self) -> None:
        matcher = CredentialShapeMatcher()
        result = matcher.evaluate(_probe("Hello, how can I help you today?"))
        assert result is None

    def test_determinism(self) -> None:
        matcher = CredentialShapeMatcher()
        probe = _probe("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
        a = matcher.evaluate(probe)
        b = matcher.evaluate(probe)
        assert a is not None and b is not None
        assert a.evidence == b.evidence

    def test_tool_calls_surface(self) -> None:
        matcher = CredentialShapeMatcher()
        probe = ProbeResult(
            variant_id="test-v0",
            seed_id="test-s0",
            attack_class="test-class",
            response_text="nothing here",
            tool_calls=({"name": "send", "args": {"url": "AKIAIOSFODNN7EXAMPLE"}},),
            raw_response=None,
        )
        result = matcher.evaluate(probe)
        assert result is not None


class TestWithExtraCredentialRules:
    def test_extends_rules(self) -> None:
        extra = StructuralRule(
            rule_id="custom_test",
            pattern=r"CUSTOM_LEAK_[0-9]+",
            surfaces=("response_text",),
        )
        matcher = with_extra_credential_rules([extra])
        assert len(matcher.rules) == len(CREDENTIAL_RULES) + 1
        result = matcher.evaluate(_probe("CUSTOM_LEAK_12345"))
        assert result is not None
        rule_ids = [h["rule"] for h in result.evidence["hits"]]
        assert "custom_test" in rule_ids
