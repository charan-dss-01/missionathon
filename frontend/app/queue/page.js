'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  CheckSquare,
  ShieldAlert,
  AlertTriangle,
  Clock,
  ArrowUpRight,
  Save,
  CheckCircle2,
  RefreshCw,
  UsersRound,
  ArrowRight
} from 'lucide-react';
import { fetchInvestigations, updateReviewStatus } from '@/lib/api';
import RiskScoreBadge from '@/components/RiskScoreBadge';
import { useAuth } from '@/components/AuthProvider';

export default function HumanReviewQueuePage() {
  const { user } = useAuth();
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState(null);
  const [editStatus, setEditStatus] = useState('NEW');
  const [editNotes, setEditNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const list = await fetchInvestigations();
      setInvestigations(list || []);
      if (list && list.length > 0 && !selectedCase) {
        setSelectedCase(list[0]);
        setEditStatus(list[0].review_status || 'NEW');
        setEditNotes(list[0].review_notes || '');
      }
    } catch (e) {
      console.warn('Failed to load review queue:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const selectCaseForReview = (inv) => {
    setSelectedCase(inv);
    setEditStatus(inv.review_status || 'NEW');
    setEditNotes(inv.review_notes || '');
  };

  const handleSaveTriage = async () => {
    if (!selectedCase) return;
    setSaving(true);
    try {
      const updated = await updateReviewStatus(selectedCase.id, editStatus, editNotes);
      setSelectedCase(updated);
      setInvestigations((prev) =>
        prev.map((i) => (i.id === updated.id ? updated : i))
      );
      setToastMsg('Triage decision committed to MongoDB.');
      setTimeout(() => setToastMsg(''), 3000);
    } catch (err) {
      alert('Error saving triage status: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const untriagedCount = investigations.filter(
    (i) => (i.review_status || 'NEW') === 'NEW'
  ).length;
  const inReviewCount = investigations.filter(
    (i) => i.review_status === 'IN_REVIEW'
  ).length;
  const resolvedCount = investigations.filter((i) =>
    (i.review_status || '').startsWith('RESOLVED')
  ).length;

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            HUMAN IN THE LOOP
          </span>
          <h1>
            Human review<span className="heading-dot">.</span>
          </h1>
          <p>
            Every agent. Every decision. Keep exceptions from becoming blind spots.
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            onClick={loadData}
            title="Refresh review queue"
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. Metric Counters */}
      <div className="metric-grid">
        <div className="metric-card">
          <div className="metric-label">
            <span>Awaiting Review</span>
            <UsersRound className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono">
            {untriagedCount < 10 ? `0${untriagedCount}` : untriagedCount}
            <span className="metric-unit">open</span>
          </div>
          <div className="metric-foot">
            <span className="text-warning">Requires analyst perspective</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>In Active Triage</span>
            <Clock className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono">
            {inReviewCount < 10 ? `0${inReviewCount}` : inReviewCount}
            <span className="metric-unit">active</span>
          </div>
          <div className="metric-foot">
            <span>Analyst assigned</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Resolved &amp; Closed</span>
            <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono">
            {resolvedCount < 10 ? `0${resolvedCount}` : resolvedCount}
            <span className="metric-unit">closed</span>
          </div>
          <div className="metric-foot">
            <span className="text-success">Disposition verified</span>
          </div>
        </div>

        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>Total In Queue</span>
            <CheckSquare className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono">
            {investigations.length < 10 ? `0${investigations.length}` : investigations.length}
            <span className="metric-unit">cases</span>
          </div>
          <div className="metric-foot">
            <span>MongoDB Atlas synced</span>
          </div>
        </div>
      </div>

      {/* 3. Master Detail Split Board */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Case List */}
        <div className="lg:col-span-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground px-1 pb-1">
            <span className="font-mono uppercase font-semibold">
              Queue Cases ({investigations.length})
            </span>
            <span>Select to inspect</span>
          </div>

          <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
            {investigations.length === 0 ? (
              <div className="p-8 border border-border bg-card rounded-md text-center text-xs text-muted-foreground">
                No cases awaiting human review.
              </div>
            ) : (
              investigations.map((inv) => {
                const isSelected = selectedCase?.id === inv.id;
                const isHigh = inv.risk?.overall_rating === 'HIGH';
                return (
                  <div
                    key={inv.id}
                    onClick={() => selectCaseForReview(inv)}
                    className={`p-3.5 rounded-md border transition cursor-pointer space-y-2 ${
                      isSelected
                        ? 'bg-card border-primary ring-1 ring-primary'
                        : 'bg-card/70 hover:bg-card border-border'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-foreground">
                        {inv.id}
                      </span>
                      <span
                        className={`status-badge badge-small ${
                          isHigh ? 'tone-danger' : 'tone-warning'
                        }`}
                      >
                        {inv.risk?.overall_rating || 'LOW'} · {inv.risk?.overall_score || 0}/100
                      </span>
                    </div>

                    <p className="text-xs text-muted-foreground truncate">
                      {inv.email_metadata?.subject || inv.input_type || 'Intake Scan'}
                    </p>

                    <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono pt-1 border-t border-border">
                      <span>Status: {inv.review_status || 'NEW'}</span>
                      <span>{inv.evidence?.length || 0} rule findings</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Inspector */}
        <div className="lg:col-span-7">
          {selectedCase ? (
            <div className="bg-card border border-border rounded-md p-6 space-y-5">
              <div className="flex items-center justify-between border-b border-border pb-4">
                <div>
                  <span className="eyebrow">CASE INSPECTOR</span>
                  <h3 className="text-base font-bold text-foreground font-mono">
                    {selectedCase.id}
                  </h3>
                </div>
                <Link
                  href={`/investigations/${selectedCase.id}`}
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline font-medium"
                >
                  Full Dossier <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>

              {/* Case Metadata Breakdown */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-2.5 rounded bg-background border border-border">
                  <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                    Calculated Score
                  </span>
                  <span className="font-bold font-mono text-foreground text-sm">
                    {selectedCase.risk?.overall_score || 0}/100 ({selectedCase.risk?.overall_rating || 'LOW'})
                  </span>
                </div>
                <div className="p-2.5 rounded bg-background border border-border">
                  <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                    Analysis Type
                  </span>
                  <span className="font-mono text-foreground">
                    {selectedCase.input_type || 'raw_text'}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-background border border-border">
                  <span className="text-[10px] text-muted-foreground uppercase font-mono block">
                    LLM Provider
                  </span>
                  <span className="font-mono text-foreground">
                    {selectedCase.llm_interpretation?.provider || 'rules'}
                  </span>
                </div>
              </div>

              {/* AI Case Summary Quote */}
              {selectedCase.llm_interpretation?.summary && (
                <div className="review-notice p-3.5 rounded border border-border bg-background text-xs leading-relaxed space-y-1">
                  <strong className="text-foreground block text-[11px] font-semibold font-mono uppercase">
                    AI Threat Summary:
                  </strong>
                  <p className="text-muted-foreground text-[11px]">
                    {selectedCase.llm_interpretation.summary}
                  </p>
                </div>
              )}

              {/* Authoritative Findings List */}
              <div className="space-y-2">
                <span className="text-[10px] text-muted-foreground font-mono uppercase font-semibold">
                  Rule Detections Requiring Human Review:
                </span>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {(selectedCase.evidence || []).map((e, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded bg-background border border-border text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-foreground">{e.title}</span>
                        <span className="font-mono text-[10px] text-primary">{e.rule_id}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground font-mono">
                        {e.supporting_observation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Disposition Form */}
              <div className="pt-4 border-t border-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-foreground uppercase font-mono">
                    Commit Disposition:
                  </span>
                  {toastMsg && (
                    <span className="text-xs font-mono text-success font-semibold">
                      ✓ {toastMsg}
                    </span>
                  )}
                </div>

                <div className="flex flex-wrap gap-2">
                  {[
                    { id: 'NEW', label: 'NEW' },
                    { id: 'IN_REVIEW', label: 'IN REVIEW' },
                    { id: 'RESOLVED_MALICIOUS', label: 'RESOLVED MALICIOUS' },
                    { id: 'RESOLVED_BENIGN', label: 'RESOLVED BENIGN' }
                  ].map((st) => (
                    <button
                      key={st.id}
                      type="button"
                      onClick={() => setEditStatus(st.id)}
                      className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                        editStatus === st.id
                          ? 'bg-primary text-primary-foreground font-semibold'
                          : 'border border-input bg-background hover:bg-accent text-muted-foreground'
                      }`}
                    >
                      {st.label}
                    </button>
                  ))}
                </div>

                <div>
                  <textarea
                    rows={3}
                    value={editNotes}
                    onChange={(e) => setEditNotes(e.target.value)}
                    placeholder="Enter analyst review notes, containment directives, or remediation logs..."
                    className="w-full bg-background border border-input rounded p-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                <button
                  onClick={handleSaveTriage}
                  disabled={saving}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 bg-primary text-primary-foreground text-xs rounded-md font-medium hover:opacity-90 cursor-pointer disabled:opacity-50"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{saving ? 'Saving...' : 'Commit Triage Decision'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="p-12 border border-border bg-card rounded-md text-center text-xs text-muted-foreground">
              Select an investigation case from the queue to inspect evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
