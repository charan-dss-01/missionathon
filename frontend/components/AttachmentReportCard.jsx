'use client';

import React, { useState } from 'react';
import {
  Paperclip,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  FileCode,
  FileArchive,
  FileSpreadsheet,
  FileText,
  Lock,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  HelpCircle,
  Flag,
  CornerDownRight
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export default function AttachmentReportCard({
  attachment,
  index = 0,
  onReportIssue
}) {
  const [showEvidence, setShowEvidence] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  if (!attachment) return null;

  const filename = attachment.filename || `attachment_${index + 1}`;
  const detectedType = attachment.detected_type || 'UNKNOWN';
  const declaredMime = attachment.declared_mime || 'unspecified';
  const sizeFormatted = formatBytes(attachment.size_bytes);
  const coverage = attachment.coverage_status || 'SCANNED';
  const score = attachment.risk_score ?? 0;
  const rating = (attachment.risk_level || (score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW')).toUpperCase();

  const isHigh = rating === 'HIGH';
  const isMedium = rating === 'MEDIUM';
  const isUnknown = rating === 'UNKNOWN' || rating === 'UNSCANNED' || coverage === 'UNKNOWN' || coverage === 'UNSCANNED' || coverage === 'OVERSIZED';
  const isLow = !isHigh && !isMedium && !isUnknown;

  const handleCopyHash = () => {
    if (!attachment.sha256) return;
    navigator.clipboard.writeText(attachment.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Tone badge styles
  let badgeTone = 'tone-success';
  let badgeBg = 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20';
  let bannerBg = 'bg-emerald-500/[0.04] border-emerald-500/20 text-emerald-900';
  let HeaderIcon = CheckCircle2;
  let iconColor = 'text-emerald-600';

  if (isHigh) {
    badgeTone = 'tone-danger';
    badgeBg = 'bg-red-500/10 text-red-700 border-red-500/20';
    bannerBg = 'bg-red-500/[0.04] border-red-500/25 text-red-950';
    HeaderIcon = ShieldAlert;
    iconColor = 'text-red-600';
  } else if (isMedium) {
    badgeTone = 'tone-warning';
    badgeBg = 'bg-amber-500/10 text-amber-700 border-amber-500/20';
    bannerBg = 'bg-amber-500/[0.04] border-amber-500/20 text-amber-950';
    HeaderIcon = AlertTriangle;
    iconColor = 'text-amber-600';
  } else if (isUnknown) {
    badgeTone = 'tone-warning';
    badgeBg = 'bg-blue-500/10 text-blue-700 border-blue-500/20';
    bannerBg = 'bg-blue-500/[0.04] border-blue-500/20 text-blue-950';
    HeaderIcon = HelpCircle;
    iconColor = 'text-blue-600';
  }

  // Suspicious traits collected
  const detectedTraits = [];
  if (attachment.dangerous_extension) detectedTraits.push({ label: 'Executable / Script Extension', tone: 'danger' });
  if (attachment.macro_detected) detectedTraits.push({ label: 'Active Macro / vbaProject.bin Stream', tone: 'danger' });
  if (attachment.double_extension) detectedTraits.push({ label: 'Deceptive Double Extension', tone: 'warning' });
  if (attachment.rtlo_detected) detectedTraits.push({ label: 'Unicode Right-to-Left Override (RTLO)', tone: 'danger' });
  if (attachment.active_content_detected) detectedTraits.push({ label: 'PDF Active Script /Launch Action', tone: 'warning' });
  if (attachment.forms_scripts_detected) detectedTraits.push({ label: 'Credential Password Form / Script', tone: 'danger' });
  if (attachment.encrypted) detectedTraits.push({ label: 'Password-Encrypted Archive Members', tone: 'warning' });

  const matchedRules = attachment.matched_rules || [];
  const evidenceRecords = attachment.evidence_records || [];
  const recommendation = attachment.recommended_action || (
    isHigh ? 'Do not open or execute. Quarantine file immediately and escalate to SecOps.'
    : isMedium ? 'Verify sender identity out-of-band before interacting. Do not enable active content.'
    : isUnknown ? 'Classification inconclusive: treat attachment as unknown (never assume safe).'
    : 'Standard document hygiene: verify unexpected sender requests prior to opening.'
  );

  const classificationReason = attachment.classification_reason || (
    isHigh ? `High Risk (${score}/100): Critical attack payload signatures detected.`
    : isMedium ? `Medium Risk (${score}/100): Suspicious macros or structural anomalies detected.`
    : isUnknown ? `Inconclusive (${coverage}): Attachment could not be statically verified safe.`
    : `Low Risk (${score}/100): Valid ${detectedType} structure with 0 malicious signatures.`
  );

  return (
    <div className={`rounded-lg border bg-card p-4 sm:p-5 space-y-4 transition-all shadow-sm ${
      isHigh ? 'border-red-500/30' : isMedium ? 'border-amber-500/30' : 'border-border'
    }`}>
      {/* 1. Header Row */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className={`p-2 rounded-md bg-secondary/50 border border-border shrink-0 mt-0.5 ${iconColor}`}>
            <HeaderIcon className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-foreground break-all" title={filename}>
                {filename}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-secondary text-muted-foreground">
                {sizeFormatted}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-border text-foreground">
                {detectedType}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
              {classificationReason}
            </p>
          </div>
        </div>

        {/* Individual Risk Badge & Score */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="text-right">
            <span className="text-[9px] font-mono uppercase text-muted-foreground block">Attachment Risk</span>
            <span className="font-mono text-sm font-bold text-foreground">{score}/100</span>
          </div>
          <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${badgeBg}`}>
            {rating}
          </span>
        </div>
      </div>

      {/* 2. Actionable Recommendation Banner */}
      <div className={`rounded-md border p-3.5 flex items-start gap-3 ${bannerBg}`}>
        <HeaderIcon className={`w-4 h-4 shrink-0 mt-0.5 ${iconColor}`} />
        <div className="space-y-0.5 text-xs">
          <span className="font-mono text-[10px] font-bold uppercase tracking-wider block opacity-80">
            Recommended SOC / End-User Action
          </span>
          <p className="font-medium leading-relaxed">
            {recommendation}
          </p>
        </div>
      </div>

      {/* 3. Technical File Identity & Coverage Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
        <div className="p-2.5 rounded bg-background border border-border/80">
          <span className="text-[10px] font-mono text-muted-foreground uppercase block">Declared MIME</span>
          <span className="font-mono text-[11px] text-foreground truncate block mt-0.5" title={declaredMime}>
            {declaredMime}
          </span>
        </div>
        <div className="p-2.5 rounded bg-background border border-border/80">
          <span className="text-[10px] font-mono text-muted-foreground uppercase block">Binary Magic Type</span>
          <span className="font-mono text-[11px] text-foreground truncate block mt-0.5" title={detectedType}>
            {detectedType}
          </span>
        </div>
        <div className="p-2.5 rounded bg-background border border-border/80">
          <span className="text-[10px] font-mono text-muted-foreground uppercase block">Coverage Status</span>
          <span className="font-mono text-[11px] font-medium text-foreground block mt-0.5">
            {coverage}
          </span>
        </div>
        <div className="p-2.5 rounded bg-background border border-border/80">
          <span className="text-[10px] font-mono text-muted-foreground uppercase block">SHA-256 Digest</span>
          <div className="flex items-center justify-between gap-1 mt-0.5">
            <span className="font-mono text-[10px] text-primary truncate" title={attachment.sha256}>
              {attachment.sha256 ? `${attachment.sha256.substring(0, 12)}...` : 'N/A'}
            </span>
            {attachment.sha256 && (
              <button
                type="button"
                onClick={handleCopyHash}
                className="text-muted-foreground hover:text-foreground transition p-0.5"
                title="Copy SHA-256 to clipboard"
              >
                {copiedHash ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 4. Suspicious Detected Features (if any) */}
      {detectedTraits.length > 0 && (
        <div className="space-y-1.5 pt-1">
          <span className="text-[10px] font-mono text-muted-foreground uppercase font-semibold block">
            Structural Anomaly Indicators Detected ({detectedTraits.length}):
          </span>
          <div className="flex flex-wrap gap-1.5">
            {detectedTraits.map((trait, idx) => (
              <span
                key={idx}
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border ${
                  trait.tone === 'danger'
                    ? 'bg-red-500/10 text-red-700 border-red-500/20'
                    : 'bg-amber-500/10 text-amber-700 border-amber-500/20'
                }`}
              >
                <AlertTriangle className="w-3 h-3 shrink-0" />
                <span>{trait.label}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* 5. Archive Members Preview (if archive) */}
      {attachment.archive_members && attachment.archive_members.length > 0 && (
        <div className="p-2.5 rounded bg-secondary/30 border border-border/60 text-xs space-y-1">
          <span className="text-[10px] font-mono text-muted-foreground uppercase font-semibold block">
            Archive Members Inspected ({attachment.archive_members.length}):
          </span>
          <div className="font-mono text-[10px] text-foreground flex flex-wrap gap-1.5">
            {attachment.archive_members.slice(0, 5).map((m, idx) => (
              <span key={idx} className="px-1.5 py-0.5 rounded bg-background border border-border">
                {m}
              </span>
            ))}
            {attachment.archive_members.length > 5 && (
              <span className="text-muted-foreground self-center">
                +{attachment.archive_members.length - 5} more members
              </span>
            )}
          </div>
        </div>
      )}

      {/* 6. Expandable Technical Evidence & Rules */}
      {(matchedRules.length > 0 || evidenceRecords.length > 0) && (
        <div className="border-t border-border/60 pt-3">
          <button
            type="button"
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex items-center justify-between w-full text-xs font-mono text-muted-foreground hover:text-foreground transition cursor-pointer"
          >
            <span className="flex items-center gap-1.5">
              <CornerDownRight className="w-3.5 h-3.5 text-primary" />
              <span>Evidence Records &amp; Matched Rules ({matchedRules.length || evidenceRecords.length})</span>
            </span>
            {showEvidence ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showEvidence && (
            <div className="mt-2.5 space-y-2">
              {evidenceRecords.length > 0 ? (
                evidenceRecords.map((ev, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-background border border-border text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] font-bold text-primary">
                        [{ev.rule_id}] {ev.title}
                      </span>
                      <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-secondary text-foreground">
                        {ev.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground leading-relaxed">
                      {ev.supporting_observation}
                    </p>
                  </div>
                ))
              ) : (
                <div className="p-2.5 rounded bg-background border border-border text-xs space-y-1">
                  <span className="font-mono text-[11px] text-foreground block">
                    Triggered Rule IDs: {matchedRules.join(', ')}
                  </span>
                  <p className="text-[11px] text-muted-foreground">
                    {attachment.limitations || 'Static signature inspection complete.'}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 7. Card Footer Action Bar */}
      <div className="flex items-center justify-between pt-2 border-t border-border/40 text-xs">
        <span className="text-[10px] font-mono text-muted-foreground">
          {attachment.limitations || 'Air-gapped static inspection only. Zero file execution.'}
        </span>
        {onReportIssue && (
          <button
            type="button"
            onClick={() => onReportIssue(filename)}
            className="inline-flex items-center gap-1 text-[11px] font-mono text-primary hover:underline cursor-pointer"
            title={`Report false positive or incorrect detection for ${filename}`}
          >
            <Flag className="w-3 h-3" />
            <span>Report Attachment Issue</span>
          </button>
        )}
      </div>
    </div>
  );
}
