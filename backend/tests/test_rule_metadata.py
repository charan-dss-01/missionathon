import pytest
from app.engine.rule_definitions import RULE_DEFINITIONS
from app.engine.rule_metadata import (
    RULE_METADATA,
    VALID_STAGES,
    get_metadata,
    validate_metadata_covers_rules,
)


def test_metadata_covers_all_rule_definitions():
    """Assert every key in RULE_DEFINITIONS has corresponding presentation metadata."""
    missing = set(RULE_DEFINITIONS.keys()) - set(RULE_METADATA.keys())
    assert not missing, f"Rules missing presentation metadata: {missing}"


def test_every_stage_value_is_valid():
    """Assert that every stage value in RULE_METADATA is one of ('lure', 'deception', 'delivery', 'action')."""
    for rule_id, meta in RULE_METADATA.items():
        assert "stage" in meta, f"Rule {rule_id} missing stage"
        assert meta["stage"] in VALID_STAGES, (
            f"Rule {rule_id} has invalid stage '{meta['stage']}'. Must be one of {VALID_STAGES}"
        )


def test_presentation_fields_present_and_non_empty():
    """Assert plain_text, hint, mitre_id, and mitre_name are present on all defined rules."""
    for rule_id, meta in RULE_METADATA.items():
        assert isinstance(meta.get("plain_text"), str) and len(meta["plain_text"]) > 0, (
            f"Rule {rule_id} missing plain_text description"
        )
        assert isinstance(meta.get("hint"), str) and len(meta["hint"]) > 0, (
            f"Rule {rule_id} missing hint guidance"
        )
        assert "mitre_id" in meta and meta["mitre_id"] is not None, (
            f"Rule {rule_id} missing mitre_id"
        )
        assert "mitre_name" in meta and meta["mitre_name"] is not None, (
            f"Rule {rule_id} missing mitre_name"
        )


def test_get_metadata_known_rule():
    """Assert get_metadata returns correct dict for known rule IDs."""
    meta = get_metadata("AUTH_SPF_FAIL")
    assert meta["stage"] == "deception"
    assert meta["mitre_id"] == "T1036"
    assert meta["mitre_name"] == "Masquerading"
    assert "plain_text" in meta
    assert "hint" in meta


def test_get_metadata_unknown_rule_safe_defaults():
    """Assert get_metadata returns safe defaults (stage 'deception', no mitre) for unknown or None rule IDs."""
    for unknown_id in ["UNKNOWN_RULE_999", None, ""]:
        meta = get_metadata(unknown_id)
        assert meta["stage"] == "deception"
        assert meta["mitre_id"] is None
        assert meta["mitre_name"] is None
        assert isinstance(meta["plain_text"], str) and len(meta["plain_text"]) > 0
        assert isinstance(meta["hint"], str) and len(meta["hint"]) > 0


def test_validate_metadata_covers_rules_function():
    """Assert validate_metadata_covers_rules() returns True on the complete ruleset."""
    assert validate_metadata_covers_rules() is True
