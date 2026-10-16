'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Eye, ShieldAlert, Info, FileText, Link as LinkIcon, Paperclip, User, CornerDownRight } from 'lucide-react';

function simpleDefang(url) {
  if (!url) return '';
  return String(url)
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/(?<!\[)\.(?!\])/g, '[.]');
}

export default function VictimTruthView({
  insights = null,
  metadata = null,
  attachments = [],
  urls = [],
  evidence = []
}) {
  const [mode, setMode] = useState('victim'); // 'victim' | 'truth'

  // Extract deceptions from insights, or derive from evidence/urls/metadata as safety fallback
  const rawDeceptions = [...(insights?.deceptions || [])];

  // Fallback 1: display name spoof
  if (!rawDeceptions.some((d) => d.kind === 'display_name_spoof')) {
    const hasSpoof = evidence.some((e) => e.rule_id === 'HDR_DISPLAY_NAME_SPOOF');
    if (hasSpoof && metadata?.display_name && metadata?.sender) {
      rawDeceptions.push({
        kind: 'display_name_spoof',
        shown: metadata.display_name,
        actual: metadata.sender,
        rule_ids: ['HDR_DISPLAY_NAME_SPOOF'],
        explanation: `Sender display name '${metadata.display_name}' masquerades as a trusted entity, but the actual underlying sender address is '${metadata.sender}'.`
      });
    }
  }

  // Fallback 2: reply-to mismatch
  if (!rawDeceptions.some((d) => d.kind === 'reply_to_mismatch')) {
    const hasReplyMismatch = evidence.some((e) => e.rule_id === 'HDR_REPLYTO_MISMATCH');
    if (
      (hasReplyMismatch ||
        (metadata?.reply_to &&
          metadata?.sender &&
          metadata.reply_to.toLowerCase() !== metadata.sender.toLowerCase())) &&
      metadata?.reply_to
    ) {
      rawDeceptions.push({
        kind: 'reply_to_mismatch',
        shown: metadata.sender,
        actual: metadata.reply_to,
        rule_ids: ['HDR_REPLYTO_MISMATCH'],
        explanation: `The visible From address is '${metadata.sender}', but user replies will be diverted to '${metadata.reply_to}'.`
      });
    }
  }

  // Fallback 3: link text vs href mismatch
  if (!rawDeceptions.some((d) => d.kind === 'link_text_vs_href')) {
    const mismatchUrls = urls.filter(
      (u) =>
        u.is_text_mismatch ||
        (u.matched_rules && u.matched_rules.includes('URL_TEXT_HREF_MISMATCH')) ||
        (u.display_text && u.display_text.trim() && u.display_text.trim() !== u.url.trim())
    );
    mismatchUrls.forEach((u) => {
      rawDeceptions.push({
        kind: 'link_text_vs_href',
        shown: simpleDefang(u.display_text || u.url),
        actual: simpleDefang(u.url),
        rule_ids: ['URL_TEXT_HREF_MISMATCH'],
        explanation: `Visible anchor text displays '${simpleDefang(u.display_text || u.url)}', but the hyperlink destination directs to '${simpleDefang(u.url)}'.`
      });
    });
  }

  // Fallback 4: RTLO attachment
  if (!rawDeceptions.some((d) => d.kind === 'rtlo_override')) {
    const rtloAtt = attachments.filter(
      (a) => a.rtlo_detected || (a.filename && a.filename.includes('\u202e'))
    );
    rtloAtt.forEach((a) => {
      rawDeceptions.push({
        kind: 'rtlo_override',
        shown: a.filename,
        actual: a.filename.replace(/\u202e/g, ''),
        rule_ids: ['ATT_RTLO_DETECTED'],
        explanation: `Attachment visually disguises its extension using Unicode Right-to-Left Override; real underlying filename is '${a.filename.replace(/\u202e/g, '')}'.`
      });
    });
  }

  // Fallback 5: Extension / MIME type mismatch
  if (!rawDeceptions.some((d) => d.kind === 'extension_vs_detected_type')) {
    const typeAtt = attachments.filter(
      (a) =>
        (a.matched_rules && a.matched_rules.includes('ATT_MIME_MISMATCH')) ||
        (a.detected_type && a.detected_type !== 'UNKNOWN' && a.detected_type.includes('Executable'))
    );
    typeAtt.forEach((a) => {
      rawDeceptions.push({
        kind: 'extension_vs_detected_type',
        shown: a.filename,
        actual: a.detected_type,
        rule_ids: ['ATT_MIME_MISMATCH'],
        explanation: `Attachment is presented as '${a.filename}', but file signature analysis indicates it is actually '${a.detected_type}'.`
      });
    });
  }

  const deceptions = rawDeceptions;
  const hasDeceptions = deceptions.length > 0;

  // Specific deception lookups
  const spoofDec = deceptions.find((d) => d.kind === 'display_name_spoof');
  const replyDec = deceptions.find((d) => d.kind === 'reply_to_mismatch');
  const linkDecs = deceptions.filter((d) => d.kind === 'link_text_vs_href');
  const rtloDecs = deceptions.filter((d) => d.kind === 'rtlo_override');
  const typeDecs = deceptions.filter((d) => d.kind === 'extension_vs_detected_type');

  return (
    <section className="vt-container">
      {/* Header with Title and Mode Switcher */}
      <div className="vt-header">
        <div>
          <span className="eyebrow">VISUAL RECONSTRUCTION</span>
          <h3 className="vt-title">Victim Experience vs Forensic Truth</h3>
          <p className="vt-subtitle">
            Toggle between the recipient&apos;s deceptive inbox perspective and verified forensic reality.
          </p>
        </div>

        <div className="vt-toggle-wrapper">
          <div className="vt-toggle">
            <button
              type="button"
              onClick={() => setMode('victim')}
              className={`vt-toggle-btn ${mode === 'victim' ? 'active-victim' : ''}`}
            >
              <Eye className="w-3.5 h-3.5 inline mr-1" />
              <span>Victim View</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('truth')}
              className={`vt-toggle-btn ${mode === 'truth' ? 'active-truth' : ''}`}
            >
              <ShieldAlert className="w-3.5 h-3.5 inline mr-1" />
              <span>Truth View</span>
            </button>
          </div>
        </div>
      </div>

      {/* Case 1: Neutral message when insights is null or has no deceptions */}
      {!hasDeceptions ? (
        <div className="vt-neutral-notice">
          <Info className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
          <div className="space-y-1">
            <strong className="text-xs text-foreground block">
              No deceptive elements detected. This does not guarantee the message is safe.
            </strong>
            <p className="text-[11px] text-muted-foreground">
              No display-name spoofing, deceptive anchor mismatches, RTLO Unicode overrides, or binary signature divergences were found.
            </p>
          </div>
        </div>
      ) : (
        /* Case 2: Interactive view with animated transition */
        <AnimatePresence mode="wait">
          <motion.div
            key={mode}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
            className={`vt-card ${mode === 'truth' ? 'vt-card-truth' : 'vt-card-victim'}`}
          >
            {/* Mode Banner Indicator */}
            <div className="vt-banner">
              {mode === 'victim' ? (
                <div className="flex items-center gap-2 text-xs text-foreground">
                  <span className="vt-dot tone-info" />
                  <strong>Simulated Recipient View:</strong>
                  <span className="text-muted-foreground text-[11px]">
                    What the victim sees in an ordinary desktop or mobile email client.
                  </span>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-xs text-danger font-medium">
                  <span className="vt-dot tone-danger" />
                  <strong>SOC Forensic Truth View:</strong>
                  <span className="text-muted-foreground text-[11px]">
                    Deceptive items swapped for real values, marked with red outlines and rule badges.
                  </span>
                </div>
              )}
            </div>

            <div className="vt-fields-grid">
              {/* Field 1: Sender / From */}
              <div className="vt-field-row">
                <span className="vt-field-label">
                  <User className="w-3 h-3 inline mr-1 text-muted-foreground" />
                  From Header:
                </span>
                <div className="vt-field-content">
                  {mode === 'victim' ? (
                    <span className="vt-text">
                      {metadata?.display_name ? (
                        <>
                          <strong className="text-foreground">{metadata.display_name}</strong>{' '}
                          <span className="text-muted-foreground text-xs">&lt;{metadata?.sender}&gt;</span>
                        </>
                      ) : (
                        metadata?.sender || 'Unknown Sender'
                      )}
                    </span>
                  ) : spoofDec ? (
                    <div className="vt-swapped">
                      <div className="flex items-center justify-between gap-2">
                        <code className="vt-code text-danger font-bold">{spoofDec.actual}</code>
                        <span className="vt-badge">{spoofDec.rule_ids[0] || 'HDR_DISPLAY_NAME_SPOOF'}</span>
                      </div>
                      <p className="vt-swapped-desc">{spoofDec.explanation}</p>
                    </div>
                  ) : (
                    <span className="vt-text text-foreground">{metadata?.sender || 'Verified Sender'}</span>
                  )}
                </div>
              </div>

              {/* Field 2: Reply-To Destination */}
              {(replyDec || metadata?.reply_to) && (
                <div className="vt-field-row">
                  <span className="vt-field-label">
                    <CornerDownRight className="w-3 h-3 inline mr-1 text-muted-foreground" />
                    Reply Route:
                  </span>
                  <div className="vt-field-content">
                    {mode === 'victim' ? (
                      <span className="vt-text text-muted-foreground">
                        {metadata?.sender ? `Replies route to ${metadata.sender}` : 'Default Sender Reply'}
                      </span>
                    ) : replyDec ? (
                      <div className="vt-swapped">
                        <div className="flex items-center justify-between gap-2">
                          <code className="vt-code text-danger font-bold">{replyDec.actual}</code>
                          <span className="vt-badge">{replyDec.rule_ids[0] || 'HDR_REPLYTO_MISMATCH'}</span>
                        </div>
                        <p className="vt-swapped-desc">{replyDec.explanation}</p>
                      </div>
                    ) : (
                      <span className="vt-text">{metadata?.reply_to}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Field 3: Subject */}
              <div className="vt-field-row">
                <span className="vt-field-label">
                  <FileText className="w-3 h-3 inline mr-1 text-muted-foreground" />
                  Subject Line:
                </span>
                <div className="vt-field-content">
                  <span className="vt-text font-medium text-foreground">
                    {metadata?.subject || '(No subject provided)'}
                  </span>
                </div>
              </div>

              {/* Field 4: Hyperlinks (Never render as <a> anchors; use <code> only) */}
              {(linkDecs.length > 0 || urls?.length > 0) && (
                <div className="vt-field-row">
                  <span className="vt-field-label">
                    <LinkIcon className="w-3 h-3 inline mr-1 text-muted-foreground" />
                    Hyperlinks:
                  </span>
                  <div className="vt-field-content space-y-2">
                    {linkDecs.map((ld, idx) => (
                      <div key={idx}>
                        {mode === 'victim' ? (
                          <div className="p-2 rounded bg-background border border-border">
                            <span className="text-[10px] text-muted-foreground block mb-0.5">Displayed Link Text:</span>
                            <code className="vt-code text-primary font-mono">{ld.shown}</code>
                          </div>
                        ) : (
                          <div className="vt-swapped">
                            <div className="flex items-center justify-between gap-2">
                              <div>
                                <span className="text-[10px] text-muted-foreground block mb-0.5">Actual Defanged Destination:</span>
                                <code className="vt-code text-danger font-bold font-mono">{ld.actual}</code>
                              </div>
                              <span className="vt-badge">{ld.rule_ids[0] || 'URL_TEXT_HREF_MISMATCH'}</span>
                            </div>
                            <p className="vt-swapped-desc">{ld.explanation}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Field 5: Attachments (RTLO and Extension/MIME swaps) */}
              {(rtloDecs.length > 0 || typeDecs.length > 0 || attachments?.length > 0) && (
                <div className="vt-field-row">
                  <span className="vt-field-label">
                    <Paperclip className="w-3 h-3 inline mr-1 text-muted-foreground" />
                    Attachments:
                  </span>
                  <div className="vt-field-content space-y-2">
                    {/* Render RTLO deceptions */}
                    {rtloDecs.map((rd, idx) => (
                      <div key={`rtlo-${idx}`}>
                        {mode === 'victim' ? (
                          <div className="p-2 rounded bg-background border border-border">
                            <span className="text-[10px] text-muted-foreground block mb-0.5">Apparent Filename:</span>
                            <code className="vt-code text-foreground font-mono">{rd.shown}</code>
                          </div>
                        ) : (
                          <div className="vt-swapped">
                            <div className="flex items-center justify-between gap-2">
                              <div>
                                <span className="text-[10px] text-muted-foreground block mb-0.5">
                                  Real Filename (Hidden Unicode Revealed):
                                </span>
                                <code className="vt-code text-danger font-bold font-mono">
                                  {rd.shown.replace(/\u202e/g, '[RLO]')}
                                </code>
                              </div>
                              <span className="vt-badge">{rd.rule_ids[0] || 'ATT_RTLO_DETECTED'}</span>
                            </div>
                            <p className="vt-swapped-desc">{rd.explanation}</p>
                          </div>
                        )}
                      </div>
                    ))}

                    {/* Render Type/Extension mismatch deceptions */}
                    {typeDecs.map((td, idx) => (
                      <div key={`type-${idx}`}>
                        {mode === 'victim' ? (
                          <div className="p-2 rounded bg-background border border-border">
                            <span className="text-[10px] text-muted-foreground block mb-0.5">Claimed Filename:</span>
                            <code className="vt-code text-foreground font-mono">{td.shown}</code>
                          </div>
                        ) : (
                          <div className="vt-swapped">
                            <div className="flex items-center justify-between gap-2">
                              <div>
                                <span className="text-[10px] text-muted-foreground block mb-0.5">
                                  Actual Detected Binary Type:
                                </span>
                                <code className="vt-code text-danger font-bold font-mono">{td.actual}</code>
                              </div>
                              <span className="vt-badge">{td.rule_ids[0] || 'ATT_MIME_MISMATCH'}</span>
                            </div>
                            <p className="vt-swapped-desc">{td.explanation}</p>
                          </div>
                        )}
                      </div>
                    ))}

                    {/* Benign attachments without deception */}
                    {attachments &&
                      attachments.length > 0 &&
                      rtloDecs.length === 0 &&
                      typeDecs.length === 0 &&
                      attachments.map((att, idx) => (
                        <div key={`att-${idx}`} className="p-2 rounded bg-background border border-border">
                          <code className="vt-code text-foreground font-mono">
                            {att.filename || 'attachment'}
                          </code>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        </AnimatePresence>
      )}
    </section>
  );
}
