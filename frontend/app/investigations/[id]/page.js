'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  FileText,
  GitBranch,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Sparkles,
  Cpu,
  Layers,
  Link as LinkIcon,
  Paperclip,
  Info,
  Save,
  Lock,
  ChevronDown,
  Hash,
  Shield,
  FileQuestion,
  AlertOctagon,
  HelpCircle,
  Activity,
  Flag,
  MessageSquare
} from 'lucide-react';
import {
  fetchInvestigationById,
  updateReviewStatus,
  getExportDownloadUrl,
  fetchInvestigationFeedback
} from '@/lib/api';
import RiskScoreBadge from '@/components/RiskScoreBadge';
import SeverityBadge from '@/components/SeverityBadge';
import EvidenceTable from '@/components/EvidenceTable';
import ExecutionTraceTimeline from '@/components/ExecutionTraceTimeline';
import InvestigationGraph from '@/components/orchestration/InvestigationGraph';
import VictimTruthView from '@/components/VictimTruthView'; // FEATURE:victim-truth
import AttackTimeline from '@/components/AttackTimeline'; // FEATURE:timeline
import AttachmentReportCard from '@/components/AttachmentReportCard';
import ClassificationFeedbackModal from '@/components/ClassificationFeedbackModal';
import RiskVectorBreakdown from '@/components/RiskVectorBreakdown';

export default function InvestigationDossierPage() {
  const params = useParams();
  const id = params?.id;

  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('dossier');
  const [reviewStatus, setReviewStatus] = useState('NEW');
  const [reviewNotes, setReviewNotes] = useState('');
  const [updatingReview, setUpdatingReview] = useState(false);
  const [reviewToast, setReviewToast] = useState(false);
  const [traceViewMode, setTraceViewMode] = useState('graph'); // 'graph' | 'timeline'
  const [feedbackModalOpen, setFeedbackModalOpen] = useState(false);
  const [feedbackTargetAttachment, setFeedbackTargetAttachment] = useState('');
  const [feedbackHistory, setFeedbackHistory] = useState([]);

  useEffect(() => {
    if (!id) return;
    const loadDossier = async () => {
      setLoading(true);
      try {
        const data = await fetchInvestigationById(id);
        setInvestigation(data);
        setReviewStatus(data.review_status || 'NEW');
        setReviewNotes(data.review_notes || '');

        try {
          const fbRes = await fetchInvestigationFeedback(id);
          setFeedbackHistory(Array.isArray(fbRes) ? fbRes : (fbRes?.feedback || []));
        } catch (fbErr) {
          console.warn('Could not load feedback history', fbErr);
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    loadDossier();
  }, [id]);

  const handleSaveReview = async (e) => {
    e.preventDefault();
    if (!id) return;
    setUpdatingReview(true);
    try {
      await updateReviewStatus(id, reviewStatus, reviewNotes);
      setReviewToast(true);
      setTimeout(() => setReviewToast(false), 3000);
    } catch (err) {
      alert('Failed to update case review status: ' + err.message);
    } finally {
      setUpdatingReview(false);
    }
  };

  if (loading) {
    return (
      <div className="py-24 text-center space-y-3">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs font-mono text-muted-foreground">Loading forensic investigation dossier...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="p-8 border border-border bg-card rounded-md max-w-xl mx-auto my-12 text-center space-y-4">
        <AlertTriangle className="w-10 h-10 text-danger mx-auto" />
        <h2 className="text-base font-semibold text-foreground">Investigation Not Found</h2>
        <p className="text-xs text-muted-foreground leading-relaxed">
          {error || 'This investigation does not exist or access is unauthorized under tenant isolation.'}
        </p>
        <Link
          href="/overview"
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-xs rounded-md font-medium"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Operations Overview</span>
        </Link>
      </div>
    );
  }

  const { risk, evidence, llm_interpretation, email_metadata, attachments = [], urls = [] } = investigation;
  const traceList = investigation.trace || investigation.execution_trace || [];
  const isHighRisk = risk?.overall_rating === 'HIGH';
  const isUnscanned = risk?.overall_rating === 'UNSCANNED' || risk?.overall_rating === 'UNKNOWN';

  const recommendations = llm_interpretation?.actionable_recommendations || llm_interpretation?.recommended_actions || [];
  const authResults = email_metadata?.recorded_auth || {};

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading with Breadcrumb and Actions */}
      <div className="page-heading">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link
              href="/history"
              className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Workflows</span>
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-mono text-xs text-foreground font-semibold">{investigation.id}</span>
          </div>
          <h1>
            Investigation Dossier<span className="heading-dot">.</span>
          </h1>
          <p>
            Deterministic Python rule evidence, static attachment verification, and transparent risk scoring.
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            type="button"
            onClick={() => {
              setFeedbackTargetAttachment('');
              setFeedbackModalOpen(true);
            }}
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
            title="Report a false positive, false negative, or incorrect file type"
          >
            <Flag className="w-3.5 h-3.5 text-warning" />
            <span>Report Classification</span>
          </button>
          <a
            href={getExportDownloadUrl(investigation.id, 'json')}
            download
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </a>
          <a
            href={getExportDownloadUrl(investigation.id, 'csv')}
            download
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </a>
          <a
            href={getExportDownloadUrl(investigation.id, 'md')}
            download
            className="inline-flex items-center justify-center gap-1.5 bg-primary text-primary-foreground shadow-sm hover:opacity-90 h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Markdown Dossier</span>
          </a>
        </div>
      </div>

      {/* 2. Top Metric Summary Cards */}
      <div className="metric-grid">
        <div className="metric-card">
          <div className="metric-label">
            <span>Overall Threat Verdict</span>
            <ShieldAlert className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.overall_score || 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot">
            <span
              className={`status-badge badge-small ${
                isHighRisk ? 'tone-danger' : isUnscanned ? 'tone-warning' : 'tone-success'
              }`}
            >
              {risk?.overall_rating || 'LOW'}
            </span>
            <span>{evidence?.length || 0} findings verified</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Sender &amp; Auth Vector</span>
            <Layers className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.sender_score ?? 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot font-mono text-[10px]">
            <span>SPF: {authResults.spf_result || 'NONE'} | DMARC: {authResults.dmarc_result || 'NONE'}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Body &amp; Text Semantics</span>
            <FileText className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.body_score ?? 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot font-mono text-[10px]">
            <span>Urgency &amp; Credential Solicitation</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Hyperlink &amp; URL Vector</span>
            <LinkIcon className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.url_score ?? 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot font-mono text-[10px]">
            <span>{urls.length} link(s) inspected</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Attachment Vector</span>
            <Paperclip className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.attachment_score ?? 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot">
            <span>{attachments.length} attachment(s)</span>
            <span>Air-Gapped Byte Scan</span>
          </div>
        </div>

        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>AI Provider &amp; Model</span>
            <Cpu className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value health-value text-base uppercase font-mono">
            <span className="health-dot tone-info" />
            {llm_interpretation?.provider_used || 'Deterministic'}
          </div>
          <div className="metric-foot">
            <span>{llm_interpretation?.attack_vector || 'Static Rule Grounded'}</span>
            <span className="text-primary font-mono text-[10px]">
              {traceList.length} nodes
            </span>
          </div>
        </div>
      </div>

      {/* 3. Mandatory Safe Verification Guidance Card (Mission #73 Requirement) */}
      <div className="rounded-md border border-primary/30 bg-primary/5 p-4 text-xs space-y-2.5">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary shrink-0" />
          <h3 className="font-semibold text-foreground uppercase tracking-wider text-xs">
            Decision-Support Notice &amp; Mandatory Verification Steps
          </h3>
        </div>
        <p className="text-muted-foreground leading-relaxed text-[11px]">
          This tool is a decision-support system, not a definitive guarantee that an email or attachment is safe or malicious. Always follow standard verification protocols:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          <div className="p-3 rounded bg-card border border-border space-y-1">
            <strong className="text-foreground font-semibold flex items-center gap-1.5 text-xs">
              <CheckCircle2 className="w-3.5 h-3.5 text-success" />
              1. Verify Official Channel
            </strong>
            <p className="text-[11px] text-muted-foreground">
              Verify unexpected messages or requests through an independently obtained official channel (corporate directory, verified portal, or known phone number).
            </p>
          </div>
          <div className="p-3 rounded bg-card border border-border space-y-1">
            <strong className="text-foreground font-semibold flex items-center gap-1.5 text-xs">
              <AlertTriangle className="w-3.5 h-3.5 text-warning" />
              2. Protect Credentials
            </strong>
            <p className="text-[11px] text-muted-foreground">
              Never enter passwords, corporate credentials, or one-time MFA codes through links received in email messages.
            </p>
          </div>
          <div className="p-3 rounded bg-card border border-border space-y-1">
            <strong className="text-foreground font-semibold flex items-center gap-1.5 text-xs">
              <ShieldAlert className="w-3.5 h-3.5 text-danger" />
              3. Report Suspicious Messages
            </strong>
            <p className="text-[11px] text-muted-foreground">
              Immediately forward suspicious messages to your IT Security or SOC team and delete unverified attachments.
            </p>
          </div>
        </div>
        {risk?.scoring_explanation && (
          <div className="pt-2 text-[11px] font-mono text-muted-foreground border-t border-border/50">
            <span className="font-semibold text-foreground">Scoring Explanation: </span>
            {risk.scoring_explanation}
          </div>
        )}
      </div>

      {/* 4. Navigation Tabs */}
      <div className="table-tabs border-b border-border">
        <button
          onClick={() => setActiveTab('dossier')}
          className={`table-tab ${activeTab === 'dossier' ? 'active' : ''}`}
        >
          <FileText className="w-3.5 h-3.5 inline mr-1" />
          Evidence &amp; Synthesis ({evidence?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab('attachments')}
          className={`table-tab ${activeTab === 'attachments' ? 'active' : ''}`}
        >
          <Paperclip className="w-3.5 h-3.5 inline mr-1" />
          Attachment Inventory ({attachments.length})
        </button>
        <button
          onClick={() => setActiveTab('urls')}
          className={`table-tab ${activeTab === 'urls' ? 'active' : ''}`}
        >
          <LinkIcon className="w-3.5 h-3.5 inline mr-1" />
          URL Inspection ({urls.length})
        </button>
        <button
          onClick={() => setActiveTab('trace')}
          className={`table-tab ${activeTab === 'trace' ? 'active' : ''}`}
        >
          <GitBranch className="w-3.5 h-3.5 inline mr-1" />
          Execution Trace ({traceList.length})
        </button>
        {email_metadata && (
          <button
            onClick={() => setActiveTab('raw')}
            className={`table-tab ${activeTab === 'raw' ? 'active' : ''}`}
          >
            <Layers className="w-3.5 h-3.5 inline mr-1" />
            RFC 5322 Headers
          </button>
        )}
      </div>

      {/* 5. Tab 1: Dossier View */}
      {activeTab === 'dossier' && (
        <div className="space-y-6">
          {/* 4-Way Threat Vector Risk Breakdown (Mission 03 Deliverable 1) */}
          <RiskVectorBreakdown
            risk={risk}
            evidence={evidence || []}
            emailMetadata={email_metadata}
            attachments={attachments}
            urls={urls}
          />

          {/* AI Synthesis Card */}
          {llm_interpretation && (
            <div className="bg-card border border-border rounded-md p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-primary" />
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                    Tier-3 SOC Intelligence Synthesis
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground uppercase">
                  Provider: {llm_interpretation.provider_used} {llm_interpretation.fallback_used ? `(Fallback: ${llm_interpretation.fallback_reason})` : ''}
                </span>
              </div>

              <div className="text-xs text-foreground leading-relaxed whitespace-pre-line bg-background p-3.5 rounded border border-border font-sans">
                {llm_interpretation.summary}
              </div>

              {/* Recommended SOC Actions */}
              {recommendations.length > 0 && (
                <div className="pt-2">
                  <span className="text-[10px] font-mono text-muted-foreground uppercase block mb-1.5 font-semibold">
                    Actionable SOC Countermeasures:
                  </span>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {recommendations.map((act, idx) => (
                      <li
                        key={idx}
                        className="p-2 rounded bg-background border border-border flex items-start gap-2"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 text-success shrink-0 mt-0.5" />
                        <span className="text-foreground">{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          <VictimTruthView
            insights={investigation.insights}
            metadata={email_metadata}
            attachments={investigation.attachments || investigation.attachment_analysis?.attachments}
            urls={investigation.urls}
            evidence={evidence}
          /> {/* FEATURE:victim-truth */}

          <AttackTimeline timeline={investigation.insights?.timeline} /> {/* FEATURE:timeline */}

          {/* Authoritative Evidence Table */}
          <section className="space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <span className="eyebrow">DETERMINISTIC PYTHON RULES</span>
                <h3 className="text-base font-semibold text-foreground">Authoritative Evidence</h3>
              </div>
              <span className="text-xs font-mono text-muted-foreground">
                {evidence?.length || 0} findings verified
              </span>
            </div>
            <EvidenceTable evidence={evidence || []} />
          </section>

          {/* Analyst Review & Triage Box */}
          <div className="bg-card border border-border rounded-md p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                Human Analyst Case Disposition
              </h3>
              {reviewToast && (
                <span className="text-xs font-mono text-success font-semibold">
                  ✓ Triage decision saved to MongoDB
                </span>
              )}
            </div>

            <form onSubmit={handleSaveReview} className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                {['NEW', 'IN_REVIEW', 'RESOLVED_MALICIOUS', 'RESOLVED_BENIGN'].map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setReviewStatus(st)}
                    className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                      reviewStatus === st
                        ? 'bg-primary text-primary-foreground font-semibold'
                        : 'border border-input bg-background hover:bg-accent text-muted-foreground'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div>
                <textarea
                  rows={3}
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Enter SOC analyst disposition rationale, blocklist updates, or escalated incident ticket numbers..."
                  className="w-full bg-background border border-input rounded p-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <button
                type="submit"
                disabled={updatingReview}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-primary text-primary-foreground text-xs rounded-md font-medium hover:opacity-90 cursor-pointer disabled:opacity-50"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{updatingReview ? 'Persisting...' : 'Commit Triage Decision'}</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* 6. Tab 2: Attachment Inventory & Report Cards (Mission 03 Requirement) */}
      {activeTab === 'attachments' && (
        <section className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <span className="eyebrow">STATIC FORENSIC METADATA &amp; RISK REPORT CARDS</span>
              <h3 className="text-base font-semibold text-foreground">Attachment Risk Breakdown</h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setFeedbackTargetAttachment('');
                  setFeedbackModalOpen(true);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-border rounded bg-background hover:bg-accent cursor-pointer transition shadow-sm"
              >
                <Flag className="w-3.5 h-3.5 text-warning" />
                <span>Report Classification Issue</span>
              </button>
              <span className="text-xs font-mono text-muted-foreground">
                {attachments.length} attachment(s) inspected
              </span>
            </div>
          </div>

          {attachments.length === 0 ? (
            <div className="empty-state p-8 border border-border bg-card rounded-md text-center space-y-2">
              <Paperclip className="w-8 h-8 text-muted-foreground mx-auto" />
              <strong className="text-sm text-foreground block">No Attachments Identified</strong>
              <p className="text-xs text-muted-foreground max-w-md mx-auto">
                This email sample does not contain MIME attachments or multipart file streams.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {attachments.map((att, idx) => (
                  <AttachmentReportCard
                    key={`${att.filename}-${idx}`}
                    attachment={att}
                    index={idx}
                    onReportIssue={(fname) => {
                      setFeedbackTargetAttachment(fname);
                      setFeedbackModalOpen(true);
                    }}
                  />
                ))}
              </div>
            </div>
          )}

          {/* User & Analyst Classification Feedback History */}
          {feedbackHistory.length > 0 && (
            <div className="border border-border/80 rounded-md bg-card/70 p-4 space-y-3 mt-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Flag className="w-4 h-4 text-warning" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                    Analyst Classification Feedback &amp; Calibration Log ({feedbackHistory.length})
                  </h4>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">
                  Recorded for model evaluation and rule tuning
                </span>
              </div>
              <div className="space-y-2.5">
                {feedbackHistory.map((fb, idx) => (
                  <div
                    key={fb.id || idx}
                    className="p-3 bg-background border border-border rounded text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-warning/15 text-warning border border-warning/30 font-mono">
                          {fb.category?.replace(/_/g, ' ') || 'FEEDBACK'}
                        </span>
                        {fb.target_attachment && (
                          <span className="text-[11px] font-mono text-foreground font-semibold flex items-center gap-1">
                            <Paperclip className="w-3 h-3 text-muted-foreground" />
                            {fb.target_attachment}
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        {fb.submitted_at ? new Date(fb.submitted_at).toLocaleString() : 'Recent'}
                      </span>
                    </div>
                    <p className="text-muted-foreground text-[11px] leading-relaxed">
                      {fb.explanation}
                    </p>
                    {fb.original_prediction_snapshot && (
                      <div className="text-[10px] font-mono text-muted-foreground pt-1.5 border-t border-border/40 flex items-center gap-3">
                        <span>Overall Risk: {fb.original_prediction_snapshot.overall_score ?? 'N/A'}/100 ({fb.original_prediction_snapshot.overall_rating ?? 'N/A'})</span>
                        <span>Evidence Count: {fb.original_prediction_snapshot.evidence_count ?? 0}</span>
                        <span>Status: <span className="text-success font-semibold">{fb.status || 'RECORDED'}</span></span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 7. Tab 3: URL Inspection Findings (Mission #73 Mandatory Requirement) */}
      {activeTab === 'urls' && (
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <span className="eyebrow">STATIC SYNTACTIC SCAN</span>
              <h3 className="text-base font-semibold text-foreground">Extracted URL Inspection</h3>
            </div>
            <span className="text-xs font-mono text-muted-foreground">
              {urls.length} link target(s) extracted
            </span>
          </div>

          {urls.length === 0 ? (
            <div className="empty-state p-8 border border-border bg-card rounded-md text-center space-y-2">
              <LinkIcon className="w-8 h-8 text-muted-foreground mx-auto" />
              <strong className="text-sm text-foreground block">No URLs Extracted</strong>
              <p className="text-xs text-muted-foreground max-w-md mx-auto">
                No outbound links, anchor tags, or raw URLs were discovered in this sample.
              </p>
            </div>
          ) : (
            <div className="table-scroll border border-border rounded-md bg-card overflow-hidden">
              <table className="workflow-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Extracted URL Target</th>
                    <th>Domain / Host</th>
                    <th>Syntactic Indicators</th>
                    <th>Notes &amp; Limitations</th>
                  </tr>
                </thead>
                <tbody>
                  {urls.map((u, idx) => {
                    const traits = [];
                    if (u.is_ip_literal) traits.push('IP Literal');
                    if (u.is_punycode) traits.push('Punycode');
                    if (u.has_confusable_chars) traits.push('Homoglyph');
                    if (u.has_deceptive_subdomains) traits.push('Deceptive Subdomain');
                    if (u.has_embedded_userinfo) traits.push('Embedded Userinfo');
                    if (u.has_suspicious_encoding) traits.push('Double Encoding');

                    return (
                      <tr key={`${u.url}-${idx}`} className="hover:bg-muted/30 transition">
                        <td className="align-top py-2.5">
                          <SeverityBadge severity={u.severity} />
                        </td>
                        <td className="align-top py-2.5 font-mono text-xs text-foreground max-w-md">
                          <div className="truncate font-medium text-primary select-all" title={u.url}>
                            {u.url}
                          </div>
                          {u.display_text && (
                            <div className="text-[10px] text-muted-foreground mt-0.5">
                              Visible Anchor: &ldquo;{u.display_text}&rdquo;
                            </div>
                          )}
                        </td>
                        <td className="align-top py-2.5 font-mono text-xs text-muted-foreground">
                          {u.domain || 'N/A'}
                        </td>
                        <td className="align-top py-2.5">
                          {traits.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {traits.map((t) => (
                                <span
                                  key={t}
                                  className="px-1.5 py-0.5 rounded bg-danger/10 text-danger text-[10px] font-mono border border-danger/20 font-semibold"
                                >
                                  {t}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-[11px] text-muted-foreground">Standard Syntax</span>
                          )}
                        </td>
                        <td className="align-top py-2.5 text-[11px] text-muted-foreground max-w-xs">
                          {u.notes || 'Static syntax evaluation only. No outbound HTTP/DNS query performed.'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* 8. Tab 4: Execution Trace View */}
      {activeTab === 'trace' && (
        <section className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-3">
            <div>
              <span className="eyebrow">GRAPH TIMELINE</span>
              <h3 className="text-base font-semibold text-foreground">LangGraph Node Orchestration &amp; Trace</h3>
            </div>
            <div className="flex items-center gap-3">
              <div className="table-tabs">
                <button
                  type="button"
                  onClick={() => setTraceViewMode('graph')}
                  className={`table-tab ${traceViewMode === 'graph' ? 'active' : ''}`}
                >
                  <Activity className="w-3.5 h-3.5 inline mr-1" />
                  Topology Graph
                </button>
                <button
                  type="button"
                  onClick={() => setTraceViewMode('timeline')}
                  className={`table-tab ${traceViewMode === 'timeline' ? 'active' : ''}`}
                >
                  <Clock className="w-3.5 h-3.5 inline mr-1" />
                  Linear Timeline
                </button>
              </div>
              <span className="text-xs font-mono text-muted-foreground">
                {traceList.length} nodes recorded
              </span>
            </div>
          </div>

          {traceViewMode === 'graph' ? (
            <InvestigationGraph
              trace={traceList}
              status="completed"
              result={investigation}
            />
          ) : (
            <ExecutionTraceTimeline trace={traceList} />
          )}
        </section>
      )}

      {/* 9. Tab 5: Raw Headers View */}
      {activeTab === 'raw' && email_metadata && (
        <section className="bg-card border border-border rounded-md p-5 space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Parsed RFC 5322 Headers
          </h3>
          <div className="p-3 rounded bg-background border border-border font-mono text-xs overflow-x-auto space-y-1.5">
            <div>
              <span className="text-muted-foreground">From:</span> {email_metadata.sender || 'N/A'} ({email_metadata.display_name || 'No display name'})
            </div>
            <div>
              <span className="text-muted-foreground">To:</span> {email_metadata.recipients?.join(', ') || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Subject:</span> {email_metadata.subject || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Date:</span> {email_metadata.date || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Reply-To:</span> {email_metadata.reply_to || 'None'}
            </div>
            <div>
              <span className="text-muted-foreground">Return-Path:</span> {email_metadata.return_path || 'None'}
            </div>
            <div>
              <span className="text-muted-foreground">Message-ID:</span> {email_metadata.message_id || 'None'}
            </div>
            <div className="pt-2 border-t border-border">
              <span className="text-muted-foreground font-semibold">Recorded Authentication Headers:</span>
              <div className="pl-2 mt-1 space-y-0.5 text-[11px]">
                <div>SPF Result: <span className="text-foreground">{authResults.spf_result || 'NONE'}</span></div>
                <div>DKIM Result: <span className="text-foreground">{authResults.dkim_result || 'NONE'}</span></div>
                <div>DMARC Result: <span className="text-foreground">{authResults.dmarc_result || 'NONE'}</span></div>
                {authResults.raw_header && (
                  <div className="text-[10px] text-muted-foreground break-all mt-1 bg-card p-1.5 rounded border border-border">
                    Raw: {authResults.raw_header}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* 10. Classification Feedback Modal (Mission 03) */}
      <ClassificationFeedbackModal
        isOpen={feedbackModalOpen}
        onClose={() => setFeedbackModalOpen(false)}
        investigationId={investigation.id}
        attachments={attachments}
        preselectedAttachment={feedbackTargetAttachment}
        onFeedbackSubmitted={(newFb) => {
          setFeedbackHistory((prev) => [newFb, ...prev]);
        }}
      />
    </div>
  );
}
