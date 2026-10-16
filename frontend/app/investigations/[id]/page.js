'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  Share2,
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
  ArrowUpRight,
  Save,
  Lock,
  ChevronDown
} from 'lucide-react';
import {
  fetchInvestigationById,
  updateReviewStatus,
  getExportDownloadUrl
} from '@/lib/api';
import RiskScoreBadge from '@/components/RiskScoreBadge';
import EvidenceTable from '@/components/EvidenceTable';
import ExecutionTraceTimeline from '@/components/ExecutionTraceTimeline';

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

  useEffect(() => {
    if (!id) return;
    const loadDossier = async () => {
      setLoading(true);
      try {
        const data = await fetchInvestigationById(id);
        setInvestigation(data);
        setReviewStatus(data.review_status || 'NEW');
        setReviewNotes(data.review_notes || '');
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
          href="/"
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-xs rounded-md font-medium"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Operations Overview</span>
        </Link>
      </div>
    );
  }

  const { risk, evidence, llm_interpretation, email_metadata, execution_trace } = investigation;
  const isHighRisk = risk?.overall_rating === 'HIGH';

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
            Deterministic Python rule evidence, AI synthesis, and execution timeline.
          </p>
        </div>

        <div className="page-heading-actions">
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
                isHighRisk ? 'tone-danger' : 'tone-success'
              }`}
            >
              {risk?.overall_rating || 'LOW'}
            </span>
            <span>{evidence?.length || 0} findings</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Email Vector Score</span>
            <Layers className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.email_score || 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot">
            <span>SPF/DKIM: {investigation.header_analysis?.spf_status || 'N/A'}</span>
            <span>DMARC: {investigation.header_analysis?.dmarc_status || 'N/A'}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Attachment Vector</span>
            <Paperclip className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {risk?.attachment_score || 0}
            <span className="metric-unit">/100</span>
          </div>
          <div className="metric-foot">
            <span>
              {investigation.attachment_analysis?.attachments?.length || 0} safe files
            </span>
            <span>Air-gapped</span>
          </div>
        </div>

        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>AI Provider &amp; Model</span>
            <Cpu className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value health-value text-base uppercase font-mono">
            <span className="health-dot tone-info" />
            {llm_interpretation?.provider || 'Deterministic'}
          </div>
          <div className="metric-foot">
            <span>{llm_interpretation?.model || 'Rule Templates'}</span>
            <span className="text-primary font-mono text-[10px]">
              {execution_trace?.length || 0} nodes
            </span>
          </div>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="table-tabs border-b border-border">
        <button
          onClick={() => setActiveTab('dossier')}
          className={`table-tab ${activeTab === 'dossier' ? 'active' : ''}`}
        >
          <FileText className="w-3.5 h-3.5 inline mr-1" />
          Forensic Evidence &amp; AI Synthesis
        </button>
        <button
          onClick={() => setActiveTab('trace')}
          className={`table-tab ${activeTab === 'trace' ? 'active' : ''}`}
        >
          <GitBranch className="w-3.5 h-3.5 inline mr-1" />
          LangGraph Execution Trace ({execution_trace?.length || 0})
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

      {/* 4. Tab 1: Dossier View */}
      {activeTab === 'dossier' && (
        <div className="space-y-6">
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
                  Provider: {llm_interpretation.provider} ({llm_interpretation.model})
                </span>
              </div>

              <div className="text-xs text-foreground leading-relaxed whitespace-pre-line bg-background p-3.5 rounded border border-border font-sans">
                {llm_interpretation.summary}
              </div>

              {/* Recommended SOC Actions */}
              {llm_interpretation.recommended_actions?.length > 0 && (
                <div className="pt-2">
                  <span className="text-[10px] font-mono text-muted-foreground uppercase block mb-1.5 font-semibold">
                    Actionable SOC Countermeasures:
                  </span>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {llm_interpretation.recommended_actions.map((act, idx) => (
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

      {/* 5. Tab 2: Execution Trace View */}
      {activeTab === 'trace' && (
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <span className="eyebrow">GRAPH TIMELINE</span>
              <h3 className="text-base font-semibold text-foreground">LangGraph Node Execution</h3>
            </div>
            <span className="text-xs font-mono text-muted-foreground">
              {execution_trace?.length || 0} nodes executed
            </span>
          </div>
          <ExecutionTraceTimeline trace={execution_trace || []} />
        </section>
      )}

      {/* 6. Tab 3: Raw Headers View */}
      {activeTab === 'raw' && email_metadata && (
        <section className="bg-card border border-border rounded-md p-5 space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Parsed RFC 5322 Headers
          </h3>
          <div className="p-3 rounded bg-background border border-border font-mono text-xs overflow-x-auto space-y-1.5">
            <div>
              <span className="text-muted-foreground">From:</span> {email_metadata.sender || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">To:</span> {email_metadata.recipient || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Subject:</span> {email_metadata.subject || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Date:</span> {email_metadata.date || 'N/A'}
            </div>
            <div>
              <span className="text-muted-foreground">Reply-To:</span> {email_metadata.reply_to || 'N/A'}
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
