'use client';

import React from 'react';
import { GitCommit, ShieldAlert, ArrowRight, ArrowDown, ExternalLink, Info } from 'lucide-react';

const STAGE_ORDER = ['lure', 'deception', 'delivery', 'action'];

const MITRE_NAMES = {
  'T1036': 'Masquerading',
  'T1204': 'User Execution',
  'T1566': 'Phishing',
  'T1566.001': 'Spearphishing Attachment',
  'T1566.002': 'Spearphishing Link',
  'T1027': 'Obfuscated Files or Information',
};

const STAGE_ICONS = {
  lure: '01',
  deception: '02',
  delivery: '03',
  action: '04',
};

export default function AttackTimeline({ timeline = null, insights = null }) {
  const stepsData = timeline || insights?.timeline || [];

  // Sort and filter stages in strict canonical order
  const steps = STAGE_ORDER
    .map((st) => stepsData.find((step) => (step.stage || '').toLowerCase() === st))
    .filter(Boolean);

  const scrollToRule = (ruleId) => {
    if (!ruleId) return;
    const el = document.getElementById(`evidence-row-${ruleId}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('tl-row-highlight');
      setTimeout(() => {
        el.classList.remove('tl-row-highlight');
      }, 2200);
    }
  };

  return (
    <section className="tl-container">
      {/* Section Header */}
      <div className="tl-header">
        <div>
          <span className="eyebrow">ATT&CK PROGRESSION</span>
          <h3 className="tl-title">Visual Attack Story</h3>
          <p className="tl-subtitle">
            Authoritative MITRE ATT&amp;CK stages reconstructed chronologically from verified forensic evidence.
          </p>
        </div>
      </div>

      {/* Case 1: Empty state */}
      {steps.length === 0 ? (
        <div className="tl-empty">
          <Info className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
          <span className="text-xs text-muted-foreground font-mono">
            No attack stages could be derived from the findings.
          </span>
        </div>
      ) : (
        /* Case 2: Multi-stage timeline grid */
        <div className="tl-grid">
          {steps.map((step, idx) => {
            const stageKey = (step.stage || '').toLowerCase();
            const stepNum = STAGE_ICONS[stageKey] || `0${idx + 1}`;
            const isLast = idx === steps.length - 1;

            return (
              <div key={stageKey} className="tl-step-wrapper">
                <div className={`tl-stage-card tl-stage-${stageKey}`}>
                  {/* Step Top */}
                  <div className="tl-stage-top">
                    <span className="tl-stage-num font-mono">{stepNum}</span>
                    <span className="tl-stage-badge uppercase font-mono">{stageKey}</span>
                  </div>

                  {/* Title & Summary */}
                  <h4 className="tl-stage-title">{step.title}</h4>
                  <p className="tl-stage-summary">{step.summary}</p>

                  {/* Rule Chips (Clickable, scroll & highlight) */}
                  {step.rule_ids?.length > 0 && (
                    <div className="tl-group">
                      <span className="tl-group-label">Triggered Rules:</span>
                      <div className="tl-chips">
                        {step.rule_ids.map((ruleId) => (
                          <button
                            key={ruleId}
                            type="button"
                            onClick={() => scrollToRule(ruleId)}
                            title={`Click to inspect ${ruleId} in evidence table`}
                            className="tl-rule-chip status-badge tone-info badge-small font-mono cursor-pointer"
                          >
                            <span>{ruleId}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK Chips */}
                  {step.mitre_ids?.length > 0 && (
                    <div className="tl-group">
                      <span className="tl-group-label">MITRE ATT&amp;CK:</span>
                      <div className="tl-chips">
                        {step.mitre_ids.map((mId) => {
                          const mName = MITRE_NAMES[mId] || 'Technique';
                          return (
                            <span key={mId} className="tl-mitre-chip font-mono">
                              <strong>{mId}</strong>
                              <span>{mName}</span>
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>

                {/* Connector on desktop between stages */}
                {!isLast && (
                  <div className="tl-connector-desktop">
                    <ArrowRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                )}

                {/* Connector on mobile between stages */}
                {!isLast && (
                  <div className="tl-connector-mobile">
                    <ArrowDown className="w-4 h-4 text-muted-foreground" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Footnote */}
      <p className="tl-footnote">
        MITRE mapping is indicative and based on static signals only.
      </p>
    </section>
  );
}
