"""Cross-validation and verdict rules (spec section 16)."""
from __future__ import annotations

from claude_web_forensics.analysis.correlator import Correlator, derived_source_key
from claude_web_forensics.analysis.rules import (
    R_CONFLICT,
    R_CROSS_FAMILY,
    R_DIRECT_EVIDENCE,
    R_DISQUALIFIED,
    R_NO_POSITIVE_EVIDENCE,
    R_SINGLE_FAMILY_ONLY,
    VerdictInput,
    decide,
)
from claude_web_forensics.model.entities import (
    FAMILY_CACHE,
    FAMILY_HISTORY,
    FAMILY_INDEXEDDB,
    FAMILY_MFT,
    FAMILY_SESSIONS,
    VERDICT_CONFIRMED,
    VERDICT_SUSPECTED,
    VERDICT_UNDETERMINED,
    EvidenceRecord,
    EvidenceStore,
    make_evidence_id,
)


def rec(family: str, locator: str, **attrs) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=make_evidence_id(family, "src", locator, attrs),
        artifact=family,
        artifact_family=family,
        source_path="src",
        record_locator=locator,
        attributes=attrs,
    )


def make_correlator(records) -> Correlator:
    store = EvidenceStore()
    store.extend(records)
    return Correlator(store)


def test_two_independent_families_confirm():
    records = [
        rec(FAMILY_HISTORY, "a", subtype="url", url="https://claude.ai/chat/x"),
        rec(FAMILY_CACHE, "b", cache_key="k", variant_index=0),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 2
    result = decide(VerdictInput(rule_id="R", group=group))
    assert result.verdict == VERDICT_CONFIRMED
    assert result.reason_code == R_CROSS_FAMILY


def test_history_download_and_url_chain_count_as_one():
    """downloads + downloads_url_chains are one History family (spec 16.1)."""
    records = [
        rec(FAMILY_HISTORY, "d1", subtype="download", download_id=2),
        rec(FAMILY_HISTORY, "d2", subtype="download", download_id=2),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 1
    assert decide(VerdictInput(rule_id="R", group=group)).verdict == VERDICT_SUSPECTED


def test_mft_si_and_fn_count_as_one():
    records = [
        rec(FAMILY_MFT, "si", frn="100-1", si_created="t"),
        rec(FAMILY_MFT, "fn", frn="100-1", fn_created="t"),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 1


def test_indexeddb_live_and_historical_count_as_one():
    records = [
        rec(FAMILY_INDEXEDDB, "l", leveldb="a", database="d", object_store="s",
            key_text="react-query-cache", record_state="LIVE"),
        rec(FAMILY_INDEXEDDB, "h", leveldb="a", database="d", object_store="s",
            key_text="react-query-cache", record_state="HISTORICAL_OR_DELETED"),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 1


def test_cache_raw_and_decoded_count_as_one():
    records = [
        rec(FAMILY_CACHE, "raw", cache_key="k", variant_index=0, raw_size=10),
        rec(FAMILY_CACHE, "dec", cache_key="k", variant_index=0, decoded_size=20),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 1


def test_duplicate_snss_commands_count_as_one():
    records = [
        rec(FAMILY_SESSIONS, "c1", session_file="Session_1", url="https://claude.ai/new", index=0),
        rec(FAMILY_SESSIONS, "c2", session_file="Session_1", url="https://claude.ai/new", index=0),
    ]
    group = make_correlator(records).group(records)
    assert group.independent_family_count == 1


def test_single_family_with_direct_evidence_confirms():
    records = [rec(FAMILY_CACHE, "k", cache_key="k", variant_index=0)]
    group = make_correlator(records).group(records)
    result = decide(
        VerdictInput(rule_id="R", group=group, direct_evidence=True,
                     direct_evidence_reason="allowlisted record")
    )
    assert result.verdict == VERDICT_CONFIRMED
    assert result.reason_code == R_DIRECT_EVIDENCE


def test_single_family_without_direct_evidence_is_suspected():
    records = [rec(FAMILY_CACHE, "k", cache_key="k", variant_index=0)]
    group = make_correlator(records).group(records)
    result = decide(VerdictInput(rule_id="R", group=group))
    assert result.verdict == VERDICT_SUSPECTED
    assert result.reason_code == R_SINGLE_FAMILY_ONLY


def test_no_evidence_is_undetermined_never_suspected():
    group = make_correlator([]).group([])
    result = decide(VerdictInput(rule_id="R", group=group))
    assert result.verdict == VERDICT_UNDETERMINED
    assert result.reason_code == R_NO_POSITIVE_EVIDENCE


def test_conflict_forces_undetermined():
    records = [
        rec(FAMILY_HISTORY, "a", subtype="url", url="u"),
        rec(FAMILY_CACHE, "b", cache_key="k", variant_index=0),
    ]
    group = make_correlator(records).group(records)
    result = decide(VerdictInput(rule_id="R", group=group, conflicts=["contradiction"]))
    assert result.verdict == VERDICT_UNDETERMINED
    assert result.reason_code == R_CONFLICT


def test_disqualifier_caps_at_suspected_even_with_two_families():
    records = [
        rec(FAMILY_HISTORY, "a", subtype="url", url="u"),
        rec(FAMILY_CACHE, "b", cache_key="k", variant_index=0),
    ]
    group = make_correlator(records).group(records)
    result = decide(VerdictInput(rule_id="R", group=group, disqualifiers=["draft only"]))
    assert result.verdict == VERDICT_SUSPECTED
    assert result.reason_code == R_DISQUALIFIED



def test_derived_source_key_distinguishes_real_independence():
    a = rec(FAMILY_HISTORY, "x", subtype="download", download_id=1)
    b = rec(FAMILY_HISTORY, "y", subtype="download", download_id=2)
    assert derived_source_key(a) != derived_source_key(b)

