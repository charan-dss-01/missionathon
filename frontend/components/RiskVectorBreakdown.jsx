'use client';

import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  UserCheck,
  FileText,
  Link2,
  Paperclip,
  CheckCircle2,
  HelpCircle,
  Layers,
  ArrowRight
} from 'lucide-react';

function getVectorTone(score) {
  if (score >= 60) {
    return {
      rating: 'HIGH',
      badgeTone: 'tone-danger',
      barBg: 'bg-red-500',
      borderTone: 'border-red-500/25',
      bgTone: 'bg-red-500/[0.03]',
      textTone: 'text-red-600',
    };
  }
  if (score >= 30) {
    return {
      rating: 'MEDIUM',
      badgeTone: 'tone-warning',
      barBg: 'bg-amber-500',
      borderTone: 'border-amber-500/25',
      bgTone: 'bg-amber-500/[0.03]',
      textTone: 'text-amber-600',
    };
  }
  return {
    rating: 'LOW',
    badgeTone: 'tone-success',
    barBg: 'bg-emerald-500',
    borderTone: 'border-emerald-500/20',
    bgTone: 'bg-emerald-500/[0.03]',
    textTone: 'text-emerald-600',
  };
}

export default function RiskVectorBreakdown({
  risk,
  evidence = [],
  emailMetadata = null,
  attachments = [],
  urls = []
}) {
  if (!risk) return null;

  const senderScore = risk.sender_score ?? 0;
  const bodyScore = risk.body_score ?? 0;
  const urlScore = risk.url_score ?? 0;
  const attachmentScore = risk.attachment_score ?? 0;
  const overallScore = risk.overall_score ?? 0;
  const overallRating = risk.overall_rating || 'LOW';

  // Group evidence findings by vector
  const senderEvidence = evidence.filter(e => e.category === 'headers' || e.category === 'authentication');
  const bodyEvidence = evidence.filter(e => e.category === 'body');
  const urlEvidence = evidence.filter(e => e.category === 'urls');
  const attachmentEvidence = evidence.filter(e => e.category === 'attachments');

  const senderTone = getVectorTone(senderScore);
  const bodyTone = getVectorTone(bodyScore);
  const urlTone = getVectorTone(urlScore);
  const attachmentTone = getVectorTone(attachmentScore);

  const vectors = [
    {
      id: 'sender',
      name: 'Sender Identity & Auth',
      category: 'RFC 5322 & Header Security',
      score: senderScore,
      tone: senderTone,
      icon: UserCheck,
      description: 'SPF, DKIM, DMARC alignment, From/Reply-To divergence, and display-name spoofing.',
      evidenceCount: senderEvidence.length,
      rules: senderEvidence.map(e => e.title || e.rule_id),
      subtext: emailMetadata
        ? `Sender: ${emailMetadata.sender || 'Unknown'} · SPF: ${emailMetadata.recorded_auth?.spf_result || 'NONE'}`
        : 'Header inspection completed'
    },
    {
      id: 'body',
      name: 'Email Body & Semantics',
      category: 'Linguistic & Psychological Cues',
      score: bodyScore,
      tone: bodyTone,
      icon: FileText,
      description: 'Coercive urgency, credential solicitation, fear-based pressure, and financial manipulation.',
      evidenceCount: bodyEvidence.length,
      rules: bodyEvidence.map(e => e.title || e.rule_id),
      subtext: bodyEvidence.length > 0
        ? `${bodyEvidence.length} behavioral anomaly cue(s) detected`
        : 'No high-pressure phrases or credential solicitation detected'
    },
    {
      id: 'url',
      name: 'Hyperlinks & URLs',
      category: 'Syntactic Link Destination Scan',
      score: urlScore,
      tone: urlTone,
      icon: Link2,
      description: 'Anchor text vs href mismatches, IP literals, punycode homoglyphs, and deceptive subdomains.',
      evidenceCount: urlEvidence.length,
      rules: urlEvidence.map(e => e.title || e.rule_id),
      subtext: `${urls.length} link(s) inspected · ${urlEvidence.length} indicator(s)`
    },
    {
      id: 'attachment',
      name: 'Attachments & Payloads',
      category: 'Air-Gapped Binary Static Scan',
      score: attachmentScore,
      tone: attachmentTone,
      icon: Paperclip,
      description: 'Magic byte signature mismatches, active Office macros, encrypted ZIPs, and RTLO disguised extensions.',
      evidenceCount: attachmentEvidence.length,
      rules: attachmentEvidence.map(e => e.title || e.rule_id),
      subtext: `${attachments.length} file(s) inspected · ${attachmentEvidence.length} indicator(s)`
    }
  ];

  return (
    <div className="bg-card border border-border rounded-lg p-5 space-y-4">
      {/* 1. Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3">
        <div>
          <span className="eyebrow flex items-center gap-1.5 text-primary">
            <Layers className="w-3.5 h-3.5" />
            DECISION-SUPPORT VECTOR ATTRIBUTION
          </span>
          <h3 className="text-base font-semibold text-foreground">
            Granular 4-Way Threat Vector Risk Breakdown
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Transparent attribution across the four primary email attack surfaces. Each vector is scored independently [0–100] based on verified deterministic evidence.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-muted-foreground uppercase block">
              Combined Verdict
            </span>
            <span className="font-mono font-bold text-sm text-foreground">
              {overallScore}/100
            </span>
          </div>
          <span className={`status-badge badge-small ${overallRating === 'HIGH' ? 'tone-danger' : overallRating === 'MEDIUM' ? 'tone-warning' : 'tone-success'}`}>
            {overallRating}
          </span>
        </div>
      </div>

      {/* 2. Vector Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5 pt-1">
        {vectors.map((vec) => {
          const Icon = vec.icon;
          const pct = Math.min(100, Math.max(0, vec.score));

          return (
            <div
              key={vec.id}
              className={`p-3.5 rounded-md border ${vec.tone.borderTone} ${vec.tone.bgTone} bg-card space-y-3 flex flex-col justify-between transition hover:border-primary/40`}
            >
              <div className="space-y-2">
                {/* Top line with Icon and Title */}
                <div className="flex items-start justify-between gap-1">
                  <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded bg-background border border-border ${vec.tone.textTone}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-foreground leading-tight">
                        {vec.name}
                      </h4>
                      <span className="text-[10px] font-mono text-muted-foreground block">
                        {vec.category}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Score & Rating Line */}
                <div className="flex items-baseline justify-between pt-1">
                  <div className="flex items-baseline gap-1">
                    <span className="text-xl font-bold font-mono text-foreground tracking-tight">
                      {vec.score}
                    </span>
                    <span className="text-[11px] font-mono text-muted-foreground">
                      /100
                    </span>
                  </div>
                  <span className={`status-badge badge-small ${vec.tone.badgeTone}`}>
                    {vec.tone.rating}
                  </span>
                </div>

                {/* Visual Progress Bar */}
                <div className="w-full h-1.5 rounded-full bg-secondary overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${vec.tone.barBg}`}
                    style={{ width: `${Math.max(4, pct)}%` }}
                  />
                </div>

                {/* Description */}
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  {vec.description}
                </p>
              </div>

              {/* Bottom findings pill */}
              <div className="pt-2 border-t border-border/60">
                <div className="flex items-center justify-between text-[10px] font-mono">
                  <span className="text-muted-foreground">Findings:</span>
                  <span className={`font-semibold ${vec.evidenceCount > 0 ? vec.tone.textTone : 'text-muted-foreground'}`}>
                    {vec.evidenceCount} verified rule{vec.evidenceCount === 1 ? '' : 's'}
                  </span>
                </div>
                {vec.rules.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {vec.rules.slice(0, 2).map((r, idx) => (
                      <span
                        key={idx}
                        className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-background border border-border text-foreground truncate max-w-[150px]"
                        title={r}
                      >
                        {r}
                      </span>
                    ))}
                    {vec.rules.length > 2 && (
                      <span className="text-[9px] font-mono text-muted-foreground px-1 py-0.5">
                        +{vec.rules.length - 2} more
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* 3. Aggregation Formula Summary Banner */}
      <div className="rounded-md bg-secondary/30 border border-border/80 p-3 text-xs space-y-1.5">
        <div className="flex items-center gap-1.5 text-foreground font-semibold">
          <ShieldCheck className="w-3.5 h-3.5 text-primary shrink-0" />
          <span className="text-[11px] uppercase tracking-wider font-mono">
            Deterministic Score Aggregation Model
          </span>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          PhishGuard AI evaluates threat vectors independently to prevent weak signals from dominating high-severity threats.
          The overall verdict is derived from the highest individual vector score (<strong>{Math.max(senderScore + bodyScore + urlScore, attachmentScore)}</strong>)
          plus cross-vector compounding bonus (25% of secondary vector), resulting in an authoritative score of <strong>{overallScore}/100</strong>.
        </p>
      </div>
    </div>
  );
}
