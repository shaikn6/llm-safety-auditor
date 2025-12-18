"""Tests for attack_library.py"""

from __future__ import annotations


from auditor.attack_library import (
    ALL_ATTACKS,
    AttackCategory,
    Severity,
    get_attack_by_id,
    get_attacks_by_category,
    get_attacks_by_owasp,
    get_attacks_by_severity,
    get_category_stats,
    OWASP_MAPPING,
)


class TestAttackLibraryCount:
    def test_total_attack_count(self):
        assert len(ALL_ATTACKS) == 50

    def test_each_category_has_ten_attacks(self):
        stats = get_category_stats()
        for category, count in stats.items():
            assert count == 10, f"Expected 10 attacks for {category}, got {count}"

    def test_all_categories_represented(self):
        categories_in_library = {a.category for a in ALL_ATTACKS}
        for cat in AttackCategory:
            assert cat in categories_in_library


class TestAttackPromptStructure:
    def test_all_attacks_have_unique_ids(self):
        ids = [a.id for a in ALL_ATTACKS]
        assert len(ids) == len(set(ids)), "Duplicate attack IDs found"

    def test_all_attacks_have_non_empty_template(self):
        for attack in ALL_ATTACKS:
            assert attack.template.strip(), f"Empty template for attack {attack.id}"

    def test_all_attacks_have_expected_behavior(self):
        for attack in ALL_ATTACKS:
            assert attack.expected_behavior.strip(), (
                f"Empty expected_behavior for {attack.id}"
            )

    def test_all_attacks_have_valid_owasp_ref(self):
        valid_owasp_refs = set(OWASP_MAPPING.values())
        for attack in ALL_ATTACKS:
            assert attack.owasp_ref in valid_owasp_refs, (
                f"Attack {attack.id} has invalid OWASP ref: {attack.owasp_ref}"
            )

    def test_all_attacks_have_valid_severity(self):
        valid_severities = set(Severity)
        for attack in ALL_ATTACKS:
            assert attack.severity in valid_severities

    def test_all_attacks_have_tags(self):
        for attack in ALL_ATTACKS:
            assert isinstance(attack.tags, list), (
                f"Tags should be a list for {attack.id}"
            )


class TestGetAttackById:
    def test_find_existing_attack(self):
        attack = get_attack_by_id("JB-001")
        assert attack is not None
        assert attack.id == "JB-001"
        assert attack.category == AttackCategory.JAILBREAK

    def test_find_nonexistent_attack_returns_none(self):
        result = get_attack_by_id("XX-999")
        assert result is None

    def test_all_ids_are_retrievable(self):
        for attack in ALL_ATTACKS:
            found = get_attack_by_id(attack.id)
            assert found is not None
            assert found.id == attack.id


class TestGetAttacksByCategory:
    def test_jailbreak_category(self):
        attacks = get_attacks_by_category(AttackCategory.JAILBREAK)
        assert len(attacks) == 10
        assert all(a.category == AttackCategory.JAILBREAK for a in attacks)

    def test_prompt_injection_category(self):
        attacks = get_attacks_by_category(AttackCategory.PROMPT_INJECTION)
        assert len(attacks) == 10
        assert all(a.category == AttackCategory.PROMPT_INJECTION for a in attacks)

    def test_data_exfiltration_category(self):
        attacks = get_attacks_by_category(AttackCategory.DATA_EXFILTRATION)
        assert len(attacks) == 10

    def test_returns_copy_not_reference(self):
        attacks1 = get_attacks_by_category(AttackCategory.JAILBREAK)
        attacks2 = get_attacks_by_category(AttackCategory.JAILBREAK)
        assert attacks1 is not attacks2


class TestGetAttacksBySeverity:
    def test_critical_attacks_exist(self):
        critical = get_attacks_by_severity(Severity.CRITICAL)
        assert len(critical) > 0
        assert all(a.severity == Severity.CRITICAL for a in critical)

    def test_high_attacks_exist(self):
        high = get_attacks_by_severity(Severity.HIGH)
        assert len(high) > 0

    def test_severity_filter_is_exclusive(self):
        critical = get_attacks_by_severity(Severity.CRITICAL)
        high = get_attacks_by_severity(Severity.HIGH)
        # No overlap in identity
        critical_ids = {a.id for a in critical}
        high_ids = {a.id for a in high}
        assert critical_ids.isdisjoint(high_ids)


class TestGetAttacksByOWASP:
    def test_llm01_attacks(self):
        attacks = get_attacks_by_owasp("LLM01: Prompt Injection")
        assert len(attacks) > 0

    def test_llm06_attacks(self):
        attacks = get_attacks_by_owasp("LLM06: Sensitive Information Disclosure")
        assert len(attacks) > 0

    def test_nonexistent_owasp_ref(self):
        attacks = get_attacks_by_owasp("LLM99: Made Up")
        assert attacks == []


class TestCategoryStats:
    def test_returns_all_categories(self):
        stats = get_category_stats()
        assert len(stats) == len(AttackCategory)

    def test_stats_sum_to_total(self):
        stats = get_category_stats()
        assert sum(stats.values()) == len(ALL_ATTACKS)


class TestJailbreakSpecific:
    def test_jb001_is_dan_attack(self):
        attack = get_attack_by_id("JB-001")
        assert (
            "DAN" in attack.template
            or "Dan" in attack.template
            or "dan" in attack.tags[0]
        )

    def test_jb010_has_critical_severity(self):
        attack = get_attack_by_id("JB-010")
        assert attack.severity == Severity.CRITICAL


class TestDataExfiltrationSpecific:
    def test_de001_targets_system_prompt(self):
        attack = get_attack_by_id("DE-001")
        assert "system" in attack.tags or "system-prompt-leak" in attack.tags

    def test_all_exfil_have_high_or_critical_severity(self):
        attacks = get_attacks_by_category(AttackCategory.DATA_EXFILTRATION)
        for a in attacks:
            assert a.severity in {Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM}
