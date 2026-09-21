"""Claude account UUID linkage (spec section 13).

Strict priority order only. Prohibited: applying the most recently seen account
to all past events, inventing an account UUID from an organization UUID, fuzzy
string similarity, and reading multiple residual UUIDs as an account switch.
When several candidates remain, the account is left EMPTY.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..model.entities import (
    FAMILY_CACHE,
    FAMILY_INDEXEDDB,
    FAMILY_LOCAL_STORAGE,
    EvidenceRecord,
    EvidenceStore,
)

# Linkage methods, most to least direct (spec section 13.1).
M_RECORD_OWN = "record_own_account_uuid"
M_CONVERSATION_ORG_MEMBERSHIP = "conversation_org_verified_membership"
M_API_URL_ORG_SAME_OBJECT = "api_url_org_same_object_account"
M_SINGLE_SESSION_CONTEXT = "single_unambiguous_session_context"
M_NONE = "unresolved"

_PRIORITY = {
    M_RECORD_OWN: 1,
    M_CONVERSATION_ORG_MEMBERSHIP: 2,
    M_API_URL_ORG_SAME_OBJECT: 3,
    M_SINGLE_SESSION_CONTEXT: 4,
    M_NONE: 99,
}


@dataclass
class AccountLink:
    account_uuid: str | None
    method: str
    candidates: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.account_uuid)


@dataclass
class AccountContext:
    """What the image says about accounts, without guessing."""

    account_uuids: set[str] = field(default_factory=set)
    organization_uuids: set[str] = field(default_factory=set)
    # organization_uuid -> set of account_uuids seen on the SAME object.
    org_to_accounts: dict[str, set[str]] = field(default_factory=dict)
    # conversation_uuid -> organization_uuid
    conversation_to_org: dict[str, str] = field(default_factory=dict)
    # account_uuid -> evidence ids that named it directly
    account_evidence: dict[str, list[str]] = field(default_factory=dict)
    display_names: dict[str, list[tuple[int | None, str, str]]] = field(default_factory=dict)

    @property
    def single_account(self) -> str | None:
        """The one account in this profile, or None when ambiguous."""
        return next(iter(self.account_uuids)) if len(self.account_uuids) == 1 else None


def build_account_context(store: EvidenceStore) -> AccountContext:
    ctx = AccountContext()

    for record in store:
        acct = (record.account_uuid or "").lower() or None
        org = (record.organization_uuid or "").lower() or None
        conv = (record.conversation_uuid or "").lower() or None

        if acct:
            ctx.account_uuids.add(acct)
            ctx.account_evidence.setdefault(acct, []).append(record.evidence_id)
        if org:
            ctx.organization_uuids.add(org)
        if conv and org:
            ctx.conversation_to_org.setdefault(conv, org)
        if acct and org:
            # Same object carried both -> a defensible org->account mapping.
            ctx.org_to_accounts.setdefault(org, set()).add(acct)

        attrs = record.attributes
        for key in ("account_uuid_candidates",):
            for candidate in attrs.get(key, []) or []:
                ctx.account_uuids.add(str(candidate).lower())
        for key in ("organization_uuid_candidates",):
            for candidate in attrs.get(key, []) or []:
                ctx.organization_uuids.add(str(candidate).lower())

        # Display names carry a LevelDB sequence, which gives a defensible
        # ordering for the account-rename detector.
        name = _display_name_from(record)
        if name and acct:
            seq = attrs.get("leveldb_seq_number")
            ctx.display_names.setdefault(acct, []).append(
                (seq if isinstance(seq, int) else None, name, record.evidence_id)
            )

    return ctx


def _display_name_from(record: EvidenceRecord) -> str:
    """Extract a Claude display name when a record unambiguously carries one."""
    attrs = record.attributes
    if record.artifact_family == FAMILY_LOCAL_STORAGE:
        if attrs.get("script_key") == "static-composer-greeting-data-v2":
            preview = attrs.get("value_preview") or ""
            return _greeting_name(preview)
    if record.artifact_family in (FAMILY_INDEXEDDB, FAMILY_CACHE):
        for key in ("display_name", "full_name"):
            value = attrs.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _greeting_name(text: str) -> str:
    """Claude greeting strings embed the display name as '<name>님'."""
    import re

    matches = re.findall(r'"([^"]{1,40}?)님', text)
    return matches[0] if matches else ""


def link_account(
    record: EvidenceRecord,
    ctx: AccountContext,
    extra_evidence: Iterable[EvidenceRecord] = (),
) -> AccountLink:
    """Resolve one record's account using the fixed priority order."""
    # 1) the record's own account_uuid
    if record.account_uuid:
        return AccountLink(
            account_uuid=record.account_uuid.lower(),
            method=M_RECORD_OWN,
            candidates=[record.account_uuid.lower()],
            evidence_ids=[record.evidence_id],
        )

    # 2) conversation -> organization -> verified membership mapping
    conv = (record.conversation_uuid or "").lower()
    if conv:
        org = ctx.conversation_to_org.get(conv)
        if org:
            accounts = ctx.org_to_accounts.get(org, set())
            if len(accounts) == 1:
                acct = next(iter(accounts))
                return AccountLink(
                    account_uuid=acct,
                    method=M_CONVERSATION_ORG_MEMBERSHIP,
                    candidates=sorted(accounts),
                    evidence_ids=ctx.account_evidence.get(acct, [])[:5],
                )
            if accounts:
                return AccountLink(
                    account_uuid=None,
                    method=M_NONE,
                    candidates=sorted(accounts),
                    note="multiple accounts map to this organization; not guessing",
                )

    # 3) API URL organization + an account on the same object
    org = (record.organization_uuid or "").lower()
    if org:
        accounts = ctx.org_to_accounts.get(org, set())
        if len(accounts) == 1:
            acct = next(iter(accounts))
            return AccountLink(
                account_uuid=acct,
                method=M_API_URL_ORG_SAME_OBJECT,
                candidates=sorted(accounts),
                evidence_ids=ctx.account_evidence.get(acct, [])[:5],
            )
        if accounts:
            return AccountLink(
                account_uuid=None,
                method=M_NONE,
                candidates=sorted(accounts),
                note="organization maps to multiple accounts; not guessing",
            )

    # 4) an unambiguous single-account session context
    single = ctx.single_account
    if single:
        return AccountLink(
            account_uuid=single,
            method=M_SINGLE_SESSION_CONTEXT,
            candidates=[single],
            evidence_ids=ctx.account_evidence.get(single, [])[:5],
            note="single account observed in this Chrome profile",
        )

    # 5) otherwise: empty
    return AccountLink(
        account_uuid=None,
        method=M_NONE,
        candidates=sorted(ctx.account_uuids),
        note="multiple or no account candidates; left empty by policy",
    )


def best_link(links: Iterable[AccountLink]) -> AccountLink:
    """Pick the most direct resolved link among several."""
    resolved = [link for link in links if link.resolved]
    if not resolved:
        merged: list[str] = []
        for link in links:
            for candidate in link.candidates:
                if candidate not in merged:
                    merged.append(candidate)
        return AccountLink(account_uuid=None, method=M_NONE, candidates=sorted(merged))
    return min(resolved, key=lambda link: _PRIORITY.get(link.method, 99))
