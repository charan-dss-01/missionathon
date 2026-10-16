'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  GitBranch,
  Search,
  SlidersHorizontal,
  Download,
  ArrowUpRight,
  ShieldAlert,
  RefreshCw,
  Plus,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Filter
} from 'lucide-react';
import { fetchInvestigations, getExportDownloadUrl } from '@/lib/api';
import { useAuth } from '@/components/AuthProvider';

export default function WorkflowsHistoryPage() {
  const { user } = useAuth();
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('ALL');

  const loadData = async () => {
    setLoading(true);
    try {
      const list = await fetchInvestigations();
      setInvestigations(list || []);
    } catch (e) {
      console.warn('Failed to load history:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [user]);

  const filtered = investigations.filter((inv) => {
    const s = searchTerm.toLowerCase();
    const matchesSearch =
      inv.id.toLowerCase().includes(s) ||
      (inv.email_metadata?.subject || '').toLowerCase().includes(s) ||
      (inv.email_metadata?.sender || '').toLowerCase().includes(s) ||
      (inv.input_type || '').toLowerCase().includes(s);

    if (!matchesSearch) return false;
    if (activeTab === 'HIGH') return inv.risk?.overall_rating === 'HIGH';
    if (activeTab === 'MEDIUM') return inv.risk?.overall_rating === 'MEDIUM';
    if (activeTab === 'REVIEW') return inv.review_status === 'NEW' || !inv.review_status;
    return true;
  });

  const total = investigations.length;
  const countHigh = investigations.filter(i => i.risk?.overall_rating === 'HIGH').length;
  const countMed = investigations.filter(i => i.risk?.overall_rating === 'MEDIUM').length;
  const countReview = investigations.filter(i => i.review_status === 'NEW' || !i.review_status).length;

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            TRACEABLE AUDIT TRAIL
          </span>
          <h1>
            Workflows<span className="heading-dot">.</span>
          </h1>
          <p>
            Persisted investigation records, deterministic scores, and exportable forensics.
          </p>
        </div>

        <div className="page-heading-actions">
          <Link
            href="/investigate"
            className="inline-flex items-center justify-center gap-1.5 bg-primary text-primary-foreground shadow-sm hover:opacity-90 h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </Link>
        </div>
      </div>

      {/* 2. Workflows Table Section */}
      <section className="workflows-section">
        <div className="workflow-table-section">
          {/* Table Controls */}
          <div className="table-controls">
            <div className="table-tabs">
              <button
                onClick={() => setActiveTab('ALL')}
                className={`table-tab ${activeTab === 'ALL' ? 'active' : ''}`}
              >
                All workflows <span>{total}</span>
              </button>
              <button
                onClick={() => setActiveTab('HIGH')}
                className={`table-tab ${activeTab === 'HIGH' ? 'active' : ''}`}
              >
                High risk <span>{countHigh}</span>
              </button>
              <button
                onClick={() => setActiveTab('MEDIUM')}
                className={`table-tab ${activeTab === 'MEDIUM' ? 'active' : ''}`}
              >
                Suspicious <span>{countMed}</span>
              </button>
              <button
                onClick={() => setActiveTab('REVIEW')}
                className={`table-tab ${activeTab === 'REVIEW' ? 'active' : ''}`}
              >
                In review <span>{countReview}</span>
              </button>
            </div>

            <div className="table-search-tools">
              <label className="search-field">
                <Search className="w-3.5 h-3.5 text-muted-foreground" />
                <input
                  aria-label="Search workflows"
                  placeholder="Search workflows…"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </label>
              <button
                onClick={loadData}
                title="Refresh workflow records"
                className="inline-flex items-center justify-center h-8 w-8 border border-input rounded text-muted-foreground hover:text-foreground"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
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
                  <th>Verdict Rating</th>
                  <th>Score</th>
                  <th>Triage Status</th>
                  <th>Updated (UTC)</th>
                  <th>Exports</th>
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
                    <td>
                      <div className="flex items-center gap-1 text-[11px] font-mono">
                        <a
                          href={getExportDownloadUrl(inv.id, 'json')}
                          download
                          className="hover:underline text-muted-foreground hover:text-foreground"
                          title="Download JSON"
                        >
                          JSON
                        </a>
                        <span>·</span>
                        <a
                          href={getExportDownloadUrl(inv.id, 'csv')}
                          download
                          className="hover:underline text-muted-foreground hover:text-foreground"
                          title="Download CSV"
                        >
                          CSV
                        </a>
                      </div>
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
                  Run a new investigation or clear active filters.
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setSearchTerm('');
                      setActiveTab('ALL');
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
              <span className="subtle-note"> · MongoDB Atlas persistent records</span>
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
    </div>
  );
}
