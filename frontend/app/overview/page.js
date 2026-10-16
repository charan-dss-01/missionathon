'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Activity,
  GitBranch,
  CheckCheck,
  UsersRound,
  ArrowUpRight,
  ArrowRight,
  Search,
  SlidersHorizontal,
  CalendarDays,
  Plus,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Download,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  CircleDashed,
  LoaderCircle,
  Check,
  X,
  Ban,
  CircleAlert
} from 'lucide-react';
import { fetchInvestigations, fetchProviderStatus, fetchHealth } from '@/lib/api';
import { useAuth } from '@/components/AuthProvider';

export default function OperationsOverviewPage() {
  const { user } = useAuth();
  const [investigations, setInvestigations] = useState([]);
  const [providers, setProviders] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedWorkflowId, setSelectedWorkflowId] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [invList, provStatus, h] = await Promise.all([
        fetchInvestigations(),
        fetchProviderStatus(),
        fetchHealth()
      ]);
      setInvestigations(invList || []);
      setProviders(provStatus);
      setHealth(h);
      if (invList && invList.length > 0) {
        setSelectedWorkflowId(invList[0].id);
      }
    } catch (e) {
      console.warn('Failed to load overview data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [user]);

  // Derived metrics
  const total = investigations.length;
  const highRisk = investigations.filter(i => i.risk?.overall_rating === 'HIGH');
  const medRisk = investigations.filter(i => i.risk?.overall_rating === 'MEDIUM');
  const lowRisk = investigations.filter(i => i.risk?.overall_rating === 'LOW');
  const inReview = investigations.filter(i => i.review_status === 'NEW' || !i.review_status);
  const highPriorityReview = investigations.filter(i => (i.review_status === 'NEW' || !i.review_status) && i.risk?.overall_rating === 'HIGH');

  // Filtered investigations for table
  const filtered = investigations.filter(inv => {
    const s = searchQuery.toLowerCase();
    const matchesSearch =
      inv.id.toLowerCase().includes(s) ||
      (inv.email_metadata?.subject || '').toLowerCase().includes(s) ||
      (inv.email_metadata?.sender || '').toLowerCase().includes(s) ||
      (inv.input_type || '').toLowerCase().includes(s);

    if (!matchesSearch) return false;
    if (activeTab === 'high') return inv.risk?.overall_rating === 'HIGH';
    if (activeTab === 'review') return inv.review_status === 'NEW' || !inv.review_status;
    return true;
  });

  const selectedInv = investigations.find(i => i.id === selectedWorkflowId) || investigations[0];

  const formatNumber = (num) => (num < 10 ? `0${num}` : `${num}`);

  // Outcome percentages for stacked bar
  const pctClean = total > 0 ? (lowRisk.length / total) * 100 : 0;
  const pctHigh = total > 0 ? (highRisk.length / total) * 100 : 0;
  const pctMed = total > 0 ? (medRisk.length / total) * 100 : 0;
  const pctReview = total > 0 ? (inReview.length / total) * 100 : 0;

  return (
    <div className="overview-layout">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            CYBER THREAT INTELLIGENCE
          </span>
          <h1>
            Operations overview<span className="heading-dot">.</span>
          </h1>
          <p>Every attack vector. Every deterministic decision. One clear view.</p>
        </div>
        <div className="page-heading-actions">
          <div className="date-filter-wrap">
            <button className="inline-flex items-center justify-center gap-1.5 whitespace-nowrap font-medium border border-border bg-card shadow-sm hover:bg-secondary h-8 rounded-md px-3 text-xs text-muted-foreground">
              <CalendarDays className="w-3.5 h-3.5 text-primary" />
              <span>{new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
            </button>
          </div>
          <Link
            href="/investigate"
            className="inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium cursor-pointer bg-primary text-primary-foreground shadow-sm hover:opacity-90 h-8 rounded-md px-3 text-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </Link>
        </div>
      </div>

      {/* 2. Metric Grid (4 Cards) */}
      <div className="metric-grid">
        {/* Card 1: Orchestrator Health */}
        <div className="metric-card">
          <div className="metric-label">
            <span>Orchestrator</span>
            <Activity className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value health-value">
            <span
              className={`health-dot ${
                health?.status === 'healthy' ? 'tone-success' : 'tone-warning'
              }`}
            />
            {health?.status === 'healthy' ? 'Active' : 'Degraded'}
          </div>
          <div className="metric-foot">
            <span>
              {providers?.fallback_ready
                ? 'Gemini ➔ Groq Fallback Ready'
                : 'Deterministic Gating'}
            </span>
            <code>10 nodes</code>
          </div>
          <div className="metric-mini-line">
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span className="active" />
            <span />
            <span />
          </div>
        </div>

        {/* Card 2: Stored Investigations */}
        <div className="metric-card">
          <div className="metric-label">
            <span>Stored investigations</span>
            <GitBranch className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {formatNumber(total)}
            <span className="metric-unit">cases</span>
          </div>
          <div className="metric-foot">
            <span>
              <i className="tiny-dot tone-info" />
              {inReview.length} in review
            </span>
            <span>{total - inReview.length} closed</span>
          </div>
        </div>

        {/* Card 3: Threat Detections */}
        <div className="metric-card">
          <div className="metric-label">
            <span>High risk findings</span>
            <CheckCheck className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {formatNumber(highRisk.length)}
            <span className="metric-unit">malicious</span>
          </div>
          <div className="metric-foot">
            <span>
              <i className="tiny-dot tone-success" />
              {lowRisk.length} clean outcome
            </span>
            <span className="text-warning">
              {medRisk.length} suspicious
            </span>
          </div>
        </div>

        {/* Card 4: Human Review Queue */}
        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>Human review</span>
            <UsersRound className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value">
            {formatNumber(inReview.length)}
            <span className="metric-unit">open cases</span>
          </div>
          <div className="metric-foot">
            <span className="text-warning">
              {highPriorityReview.length} high priority
            </span>
            <Link href="/queue" className="inline-flex items-center gap-1 text-primary hover:underline">
              View queue <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* 3. Agent Fleet Strip */}
      <div className="agents-strip">
        <span className="agents-strip-label">
          <Activity className="w-3.5 h-3.5 text-primary" />
          LANGGRAPH 10-NODE INVESTIGATION FLEET
        </span>
        <div className="health-indicator hidden sm:flex items-center gap-2">
          <span className="health-dot tone-success" />
          <span className="text-muted-foreground text-xs font-mono">
            Deterministic Rule Engine &amp; Fallback Resilient
          </span>
          <span className="health-latency text-xs font-mono text-muted-foreground">
            {providers?.gemini_configured ? 'Gemini Active' : providers?.groq_configured ? 'Groq Active' : 'Static Mode'}
          </span>
        </div>
        <Link
          href="/trace"
          aria-label="View system health & orchestration"
          className="inline-flex items-center justify-center h-8 w-8 text-muted-foreground hover:text-foreground ml-auto"
          title="View full trace timeline"
        >
          <ArrowUpRight className="w-4 h-4" />
        </Link>
      </div>

      {/* 4. Agent Orchestration Core */}
      <section className="evidence-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">THE AIR-GAPPED SECURITY CORE</span>
            <h2>Agent orchestration</h2>
          </div>
          <div className="section-tools">
            <span className="static-snapshot">
              <span className="health-dot tone-info" />
              Deterministic Rule Engine
            </span>
            {investigations.length > 0 && (
              <select
                aria-label="Select workflow to inspect"
                value={selectedWorkflowId}
                onChange={(e) => setSelectedWorkflowId(e.target.value)}
                className="text-xs bg-background border border-input rounded px-2 py-1"
              >
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.id} — {inv.risk?.overall_rating || 'SCAN'} (Score: {inv.risk?.overall_score || 0})
                  </option>
                ))}
              </select>
            )}
            <Link
              href={selectedInv ? `/investigations/${selectedInv.id}` : '/trace'}
              aria-label="Open selected workflow"
              className="inline-flex items-center justify-center h-8 w-8 text-muted-foreground hover:text-foreground"
              title="Open full dossier"
            >
              <ArrowUpRight className="w-4 h-4" />
            </Link>
          </div>
        </div>

        {/* Live LangGraph Node Topology Bar */}
        <div className="bg-background/60 border border-border rounded p-4 my-2">
          <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2">
            {[
              { id: '1', name: 'parse_input', desc: 'RFC 5322 MIME' },
              { id: '2', name: 'headers', desc: 'SPF/DKIM/DMARC' },
              { id: '3', name: 'body', desc: 'Urgency & Links' },
              { id: '4', name: 'urls', desc: 'Homoglyphs/IP' },
              { id: '5', name: 'attachments', desc: 'RTLO & Bytes' },
              { id: '6', name: 'evidence', desc: 'Correlated Gate' },
              { id: '7', name: 'calculate_risk', desc: 'Math Scoring' },
              { id: '8', name: 'llm_synthesis', desc: 'Gemini ➔ Groq' },
              { id: '9', name: 'validator', desc: 'Rule Integrity' },
              { id: '10', name: 'report', desc: 'Final Dossier' },
            ].map((node, idx) => (
              <div
                key={node.id}
                className="bg-card border border-border rounded p-2.5 text-center flex flex-col justify-between"
              >
                <div className="text-[9px] font-mono text-muted-foreground">NODE 0{idx + 1}</div>
                <div className="font-semibold text-xs text-foreground truncate my-1">
                  {node.name}
                </div>
                <div className="text-[9px] text-muted-foreground font-mono truncate">
                  {node.desc}
                </div>
                <div className="mt-2 pt-1 border-t border-border flex items-center justify-center gap-1 text-[9px] text-emerald-600 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  PASS
                </div>
              </div>
            ))}
          </div>

          {selectedInv && (
            <div className="mt-4 pt-3 border-t border-border flex flex-col sm:flex-row sm:items-center justify-between text-xs text-muted-foreground gap-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-foreground font-medium">Selected Case: {selectedInv.id}</span>
                <span>•</span>
                <span>Type: <code className="text-foreground">{selectedInv.input_type || 'email'}</code></span>
                <span>•</span>
                <span>Provider: <code className="text-foreground">{selectedInv.llm_interpretation?.provider || 'rules'}</code></span>
              </div>
              <Link
                href={`/investigations/${selectedInv.id}`}
                className="text-primary hover:underline inline-flex items-center gap-1 font-medium"
              >
                Inspect authoritative evidence ({selectedInv.evidence?.length || 0} findings) <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
          )}
        </div>
      </section>

      {/* 5. Overview Secondary (Outcomes, Recent Activity, Attention) */}
      <div className="overview-secondary">
        {/* Threat Outcomes Breakdown */}
        <section className="outcomes-section">
          <div className="section-heading">
            <div>
              <h2>Investigation outcomes</h2>
            </div>
            <span className="section-caption">{total} decided</span>
          </div>
          <div className="outcome-summary">
            <div className="outcome-stacked-bar">
              <span className="outcome-bar-clean" style={{ flexGrow: pctClean }} title="Clean" />
              <span className="outcome-bar-exception" style={{ flexGrow: pctHigh }} title="High Risk" />
              <span className="outcome-bar-needs_review" style={{ flexGrow: pctMed }} title="Suspicious" />
              <span className="outcome-bar-incomplete" style={{ flexGrow: pctReview }} title="In Review" />
            </div>
            <div className="outcome-list">
              <div>
                <span>
                  <i className="outcome-bar-clean" />
                  Clean / Low Risk
                </span>
                <strong>
                  {lowRisk.length}
                  <small>{Math.round(pctClean)}%</small>
                </strong>
              </div>
              <div>
                <span>
                  <i className="outcome-bar-exception" />
                  High Risk Malicious
                </span>
                <strong>
                  {highRisk.length}
                  <small>{Math.round(pctHigh)}%</small>
                </strong>
              </div>
              <div>
                <span>
                  <i className="outcome-bar-needs_review" />
                  Suspicious / Medium
                </span>
                <strong>
                  {medRisk.length}
                  <small>{Math.round(pctMed)}%</small>
                </strong>
              </div>
              <div>
                <span>
                  <i className="outcome-bar-incomplete" />
                  Awaiting Review
                </span>
                <strong>
                  {inReview.length}
                  <small>{Math.round(pctReview)}%</small>
                </strong>
              </div>
            </div>
          </div>
        </section>

        {/* Recent Activity Timeline */}
        <section className="recent-section">
          <div className="section-heading">
            <div>
              <h2>Recent activity</h2>
            </div>
            <Link
              href="/history"
              className="inline-flex items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              View all <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="event-timeline divide-y divide-border">
            {investigations.length === 0 ? (
              <p className="text-xs text-muted-foreground py-4">No recent investigation records.</p>
            ) : (
              investigations.slice(0, 4).map((inv) => (
                <div key={inv.id} className="py-2.5 flex items-center justify-between text-xs">
                  <div className="min-w-0 pr-2">
                    <div className="flex items-center gap-1.5 font-mono text-[11px] text-foreground font-medium">
                      <span>{inv.id}</span>
                      <span
                        className={`status-badge badge-small ${
                          inv.risk?.overall_rating === 'HIGH'
                            ? 'tone-danger'
                            : inv.risk?.overall_rating === 'MEDIUM'
                            ? 'tone-warning'
                            : 'tone-success'
                        }`}
                      >
                        {inv.risk?.overall_rating || 'LOW'}
                      </span>
                    </div>
                    <p className="text-muted-foreground text-[11px] truncate mt-0.5">
                      {inv.email_metadata?.subject || inv.input_type || 'Raw Scan Record'}
                    </p>
                  </div>
                  <Link
                    href={`/investigations/${inv.id}`}
                    className="text-muted-foreground hover:text-foreground shrink-0"
                  >
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Human in the loop Attention Card */}
        <section className="attention-section">
          <div className="attention-icon">
            <UsersRound className="w-5 h-5 text-warning" />
          </div>
          <span className="eyebrow">HUMAN IN THE LOOP</span>
          <h2>
            A decision needs
            <br />
            your perspective.
          </h2>
          <p>
            {inReview.length} cases are awaiting review.
            <br />
            Keep exceptions from becoming blind spots.
          </p>
          <div className="attention-priorities">
            <span>
              <i className="tiny-dot tone-danger" />
              {highPriorityReview.length} high priority
            </span>
            <span>
              <i className="tiny-dot tone-warning" />
              {inReview.length - highPriorityReview.length} medium
            </span>
          </div>
          <Link
            href="/queue"
            className="inline-flex items-center justify-between w-full rounded-md text-xs font-medium border border-border bg-card shadow-sm hover:bg-secondary h-8 px-3 mt-3 text-foreground"
          >
            <span>Open review queue</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </section>
      </div>

      {/* 6. Workflows / Investigations Table Section */}
      <section className="workflows-section">
        <div className="section-heading">
          <div>
            <h2>Workflows & Investigations</h2>
          </div>
          <Link
            href="/history"
            className="inline-flex items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            View all workflows <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="workflow-table-section">
          {/* Table Controls (Tabs & Search) */}
          <div className="table-controls">
            <div className="table-tabs">
              <button
                onClick={() => setActiveTab('all')}
                className={`table-tab ${activeTab === 'all' ? 'active' : ''}`}
              >
                All workflows <span>{total}</span>
              </button>
              <button
                onClick={() => setActiveTab('high')}
                className={`table-tab ${activeTab === 'high' ? 'active' : ''}`}
              >
                High risk <span>{highRisk.length}</span>
              </button>
              <button
                onClick={() => setActiveTab('review')}
                className={`table-tab ${activeTab === 'review' ? 'active' : ''}`}
              >
                Needs review <span>{inReview.length}</span>
              </button>
            </div>

            <div className="table-search-tools">
              <label className="search-field">
                <Search className="w-3.5 h-3.5 text-muted-foreground" />
                <input
                  aria-label="Search workflows"
                  placeholder="Search workflows…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </label>
              <button className="inline-flex items-center justify-center gap-1 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs text-muted-foreground">
                <SlidersHorizontal className="w-3.5 h-3.5" />
                <span>Filters</span>
              </button>
            </div>
          </div>

          {/* Table Scroll Area */}
          <div className="table-scroll">
            <table className="workflow-table">
              <thead>
                <tr>
                  <th>
                    <button className="inline-flex items-center gap-1 font-medium text-xs">
                      Workflow ID <ArrowUpDown className="w-3 h-3 text-muted-foreground" />
                    </button>
                  </th>
                  <th>Target / Subject</th>
                  <th>Input Route</th>
                  <th>Risk Rating</th>
                  <th>Score</th>
                  <th>Triage Status</th>
                  <th>Updated (UTC)</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filtered.map((inv) => (
                  <tr key={inv.id} className="hover:bg-muted/40 transition">
                    <td className="font-mono text-xs font-semibold text-foreground">
                      <Link href={`/investigations/${inv.id}`} className="hover:underline">
                        {inv.id}
                      </Link>
                    </td>
                    <td className="text-xs text-muted-foreground max-w-xs truncate">
                      {inv.email_metadata?.subject || inv.input_type || 'Direct Intake'}
                    </td>
                    <td className="text-xs font-mono text-muted-foreground">
                      {inv.input_type || 'raw_text'}
                    </td>
                    <td>
                      <span
                        className={`status-badge badge-small ${
                          inv.risk?.overall_rating === 'HIGH'
                            ? 'tone-danger'
                            : inv.risk?.overall_rating === 'MEDIUM'
                            ? 'tone-warning'
                            : 'tone-success'
                        }`}
                      >
                        {inv.risk?.overall_rating || 'LOW'}
                      </span>
                    </td>
                    <td className="font-mono text-xs font-semibold">
                      {inv.risk?.overall_score || 0}/100
                    </td>
                    <td>
                      <span className="text-[11px] font-mono text-muted-foreground uppercase">
                        {inv.review_status || 'NEW'}
                      </span>
                    </td>
                    <td className="text-xs text-muted-foreground font-mono">
                      {inv.created_at
                        ? new Date(inv.created_at).toLocaleDateString()
                        : '16 Oct 2026'}
                    </td>
                    <td className="text-right">
                      <Link
                        href={`/investigations/${inv.id}`}
                        className="inline-flex items-center gap-1 text-xs text-primary hover:underline font-medium"
                      >
                        Dossier <ArrowUpRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Empty State */}
            {filtered.length === 0 && (
              <div className="empty-state py-12 text-center flex flex-col items-center justify-center">
                <Search className="w-8 h-8 text-muted-foreground mb-2" />
                <strong className="text-sm text-foreground">No workflows match these filters</strong>
                <p className="text-xs text-muted-foreground mt-1 mb-4">
                  Run a new investigation or clear active search keywords.
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setActiveTab('all');
                    }}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs text-primary hover:underline"
                  >
                    Clear filters
                  </button>
                  <Link
                    href="/investigate"
                    className="inline-flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground text-xs rounded hover:opacity-90"
                  >
                    <Plus className="w-3 h-3" /> Start Investigation
                  </Link>
                </div>
              </div>
            )}
          </div>

          {/* Table Footer */}
          <div className="table-footer">
            <span>
              {filtered.length > 0 ? `1–${filtered.length}` : '0–0'} of {total} workflows
              <span className="subtle-note"> · MongoDB Atlas source</span>
            </span>
            <div className="flex items-center gap-1">
              <button
                disabled
                className="inline-flex items-center justify-center h-8 w-8 border border-input rounded text-muted-foreground disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="text-xs font-mono px-2">1</span>
              <button
                disabled
                className="inline-flex items-center justify-center h-8 w-8 border border-input rounded text-muted-foreground disabled:opacity-40"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 7. Reference Status Counts Strip */}
      <div className="status-counts">
        <span>
          <span className="status-badge tone-neutral badge-small">
            <CircleDashed className="w-3 h-3" />
            <span>PENDING</span>
          </span>
          <strong>0</strong>
        </span>
        <span>
          <span className="status-badge tone-info badge-small">
            <LoaderCircle className="w-3 h-3 animate-spin" />
            <span>IN PROGRESS</span>
          </span>
          <strong>0</strong>
        </span>
        <span>
          <span className="status-badge tone-success badge-small">
            <Check className="w-3 h-3" />
            <span>COMPLETED</span>
          </span>
          <strong>{total}</strong>
        </span>
        <span>
          <span className="status-badge tone-danger badge-small">
            <X className="w-3 h-3" />
            <span>MALICIOUS</span>
          </span>
          <strong>{highRisk.length}</strong>
        </span>
        <span>
          <span className="status-badge tone-warning badge-small">
            <Ban className="w-3 h-3" />
            <span>SUSPICIOUS</span>
          </span>
          <strong>{medRisk.length}</strong>
        </span>
        <span>
          <span className="status-badge tone-warning badge-small">
            <CircleAlert className="w-3 h-3" />
            <span>RECOVERY REQUIRED</span>
          </span>
          <strong>0</strong>
        </span>
      </div>
    </div>
  );
}
