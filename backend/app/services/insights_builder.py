"""Insights builder service: extracts deceptions, clue locations, and attack timeline from investigation findings."""

from typing import List, Dict, Any, Optional, Tuple
from app.models.schemas import (
    EmailMetadata,
    URLFinding,
    AttachmentFinding,
    EvidenceRecord,
    Deception,
    ClueLocation,
    TimelineStep,
    Insights
)
from app.engine.rule_metadata import get_metadata
from app.services.defang import defang_url

STAGE_ORDER = ["lure", "deception", "delivery", "action"]
STAGE_TITLES = {
    "lure": "Lure & Social Engineering",
    "deception": "Identity Deception & Masquerading",
    "delivery": "Threat Vector Delivery",
    "action": "Exploitation & Target Action",
}


def build_insights(
    metadata: Optional[EmailMetadata],
    plain_body: str,
    html_body: str,
    url_findings: List[URLFinding],
    attachment_findings: List[AttachmentFinding],
    evidence_records: List[EvidenceRecord]
) -> Insights:
    """
    Derives presentation insights from authoritative analysis findings:
    1. Deceptions: discrepancy between what is shown to the user and what actually exists.
    2. Clues: localized evidence tags across header, body, link, and attachment regions.
    3. Timeline: ordered progression of attack stages (lure -> deception -> delivery -> action).
    """
    deceptions: List[Deception] = []
    rule_ids_present = {ev.rule_id for ev in evidence_records}

    # 1. Deception: Display Name Spoof (shown name vs actual address)
    if metadata and metadata.display_name and metadata.sender:
        is_spoof_rule = "HDR_DISPLAY_NAME_SPOOF" in rule_ids_present
        # Flag if rule fired or if display name diverges significantly from sender
        if is_spoof_rule or (
            metadata.display_name.strip()
            and metadata.display_name.strip().lower() != metadata.sender.strip().lower()
            and any(t in metadata.display_name.lower() for t in [
                "microsoft", "google", "apple", "paypal", "amazon", "netflix",
                "it support", "security", "admin", "helpdesk", "billing"
            ])
        ):
            deceptions.append(Deception(
                kind="display_name_spoof",
                shown=metadata.display_name,
                actual=metadata.sender,
                rule_ids=["HDR_DISPLAY_NAME_SPOOF"] if is_spoof_rule else [],
                explanation=(
                    f"Sender display name '{metadata.display_name}' masquerades as a trusted entity, "
                    f"but the actual underlying sender address is '{metadata.sender}'."
                )
            ))

    # 2. Deception: Link Text vs Href (both defanged)
    for uf in url_findings:
        is_mismatch = (
            uf.is_text_mismatch
            or "URL_TEXT_HREF_MISMATCH" in uf.matched_rules
            or (
                uf.display_text
                and uf.display_text.strip()
                and uf.display_text.strip().lower() != uf.url.strip().lower()
                and ("http" in uf.display_text.lower() or "." in uf.display_text)
            )
        )
        if is_mismatch:
            shown_defanged = defang_url(uf.display_text)
            actual_defanged = defang_url(uf.url)
            deceptions.append(Deception(
                kind="link_text_vs_href",
                shown=shown_defanged,
                actual=actual_defanged,
                rule_ids=["URL_TEXT_HREF_MISMATCH"],
                explanation=(
                    f"Visible anchor text displays '{shown_defanged}', "
                    f"but the hyperlink destination directs to '{actual_defanged}'."
                )
            ))

    # 3. Deception: Attachment name vs real name after removing RTLO character
    for af in attachment_findings:
        if af.rtlo_detected or "\u202e" in af.filename or "ATT_RTLO_DETECTED" in af.matched_rules:
            clean_name = af.filename.replace("\u202e", "")
            deceptions.append(Deception(
                kind="rtlo_override",
                shown=af.filename,
                actual=clean_name,
                rule_ids=["ATT_RTLO_DETECTED"],
                explanation=(
                    f"Attachment visually disguises its extension using Unicode Right-to-Left Override; "
                    f"real underlying filename is '{clean_name}'."
                )
            ))

    # 4. Deception: Extension vs detected type (magic signature mismatch)
    for af in attachment_findings:
        has_ext_mismatch = (
            "ATT_MIME_MISMATCH" in af.matched_rules
            or "ATT_DOUBLE_EXT" in af.matched_rules
            or (af.detected_type and af.detected_type not in ["UNKNOWN", "OVERSIZED"] and "Executable" in af.detected_type)
        )
        if has_ext_mismatch and af.detected_type and af.detected_type != "UNKNOWN":
            deceptions.append(Deception(
                kind="extension_vs_detected_type",
                shown=af.filename,
                actual=af.detected_type,
                rule_ids=[r for r in ["ATT_MIME_MISMATCH", "ATT_DOUBLE_EXT", "ATT_DANGEROUS_EXT"] if r in af.matched_rules] or ["ATT_MIME_MISMATCH"],
                explanation=(
                    f"Attachment is presented as '{af.filename}', "
                    f"but file signature analysis indicates it is actually '{af.detected_type}'."
                )
            ))

    # 5. Deception: Reply-To vs From
    if metadata and metadata.reply_to and metadata.sender:
        sender_domain = metadata.sender_domain.lower() if metadata.sender_domain else metadata.sender.split("@")[-1].lower()
        reply_domain = metadata.reply_to.split("@")[-1].lower() if "@" in metadata.reply_to else ""
        is_reply_mismatch = "HDR_REPLYTO_MISMATCH" in rule_ids_present or (reply_domain and reply_domain != sender_domain)
        if is_reply_mismatch:
            deceptions.append(Deception(
                kind="reply_to_mismatch",
                shown=metadata.sender,
                actual=metadata.reply_to,
                rule_ids=["HDR_REPLYTO_MISMATCH"],
                explanation=(
                    f"The visible From address is '{metadata.sender}', "
                    f"but user replies will be diverted to '{metadata.reply_to}'."
                )
            ))

    # 2. Clues: extract localized clue references for each authoritative evidence finding
    clues: List[ClueLocation] = []
    for idx, ev in enumerate(evidence_records):
        cat = (ev.category or "").lower()
        if cat in ["headers", "authentication", "header"]:
            region = "header"
        elif cat in ["urls", "url", "link"]:
            region = "link"
        elif cat in ["attachments", "attachment"]:
            region = "attachment"
        else:
            region = "body"

        text_span = ev.source_location or ev.supporting_observation or ev.title
        if region == "link":
            text_span = defang_url(text_span)

        clues.append(ClueLocation(
            clue_id=f"clue-{idx+1}",
            rule_id=ev.rule_id,
            region=region,
            text_span=text_span,
            label=ev.title or ev.rule_id
        ))

    # 3. Timeline: group triggered rules by RULE_METADATA stage (lure -> deception -> delivery -> action)
    seen_rules = set()
    unique_rule_ids = []
    for ev in evidence_records:
        if ev.rule_id not in seen_rules:
            seen_rules.add(ev.rule_id)
            unique_rule_ids.append(ev.rule_id)

    stage_groups: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {s: [] for s in STAGE_ORDER}
    for r_id in unique_rule_ids:
        meta = get_metadata(r_id)
        st = meta.get("stage", "deception")
        if st not in stage_groups:
            st = "deception"
        stage_groups[st].append((r_id, meta))

    timeline: List[TimelineStep] = []
    for st in STAGE_ORDER:
        items = stage_groups[st]
        if not items:
            continue  # Skip empty stages

        stage_rules = [r_id for r_id, _ in items]
        mitre_ids: List[str] = []
        for _, meta in items:
            m_id = meta.get("mitre_id")
            if m_id and m_id not in mitre_ids:
                mitre_ids.append(m_id)

        plain_texts = [meta["plain_text"].strip() for _, meta in items if meta.get("plain_text")]
        if plain_texts:
            summary = " ".join(t.rstrip(".") for t in plain_texts) + "."
        else:
            summary = f"Security indicators identified in {st} stage."

        timeline.append(TimelineStep(
            stage=st,
            title=STAGE_TITLES.get(st, st.capitalize()),
            rule_ids=stage_rules,
            mitre_ids=mitre_ids,
            summary=summary
        ))

    return Insights(
        deceptions=deceptions,
        clues=clues,
        timeline=timeline
    )
