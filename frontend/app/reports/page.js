'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ScanSearch,
  Download,
  FileText,
  RefreshCw,
  ArrowUpRight,
  Shield,
  Layers,
  Lock,
  CheckCircle2,
  Database
} from 'lucide-react';
import { fetchInvestigations, getExportDownloadUrl } from '@/lib/api';
import { generateInvestigationPdf } from '@/lib/pdfGenerator';

export default function EvidenceExplorerPage() {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const list = await fetchInvestigations();
      setInvestigations(list || []);
    } catch (e) {
      console.warn('Failed to load reports:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const total = investigations.length;
  const criticals = investigations.filter((i) => i.risk?.overall_rating === 'HIGH').length;

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            EVIDENCE &amp; EXPORT HUB
          </span>
          <h1>
            Evidence explorer<span className="heading-dot">.</span>
          </h1>
          <p>
            Every rule observation. Every signature match. Exportable dossiers for compliance and SIEM ingestion.
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            onClick={loadData}
            title="Refresh records"
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. Format Specifications */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="metric-card border-red-500/25 bg-gradient-to-br from-card to-red-500/[0.04]">
          <div className="metric-label">
            <span className="font-semibold text-red-700">Executive Dossier</span>
            <FileText className="w-4 h-4 text-red-600" />
          </div>
          <div className="metric-value font-mono text-sm uppercase text-red-600 font-bold">
            .PDF Format
          </div>
          <div className="metric-foot">
            <span className="text-red-700/80 font-medium">Audit-ready executive SOC report</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Markdown Dossier</span>
            <FileText className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono text-sm uppercase">
            .MD Format
          </div>
          <div className="metric-foot">
            <span>Human-readable SOC report</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>SIEM Structured Data</span>
            <Download className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono text-sm uppercase">
            .CSV Format
          </div>
          <div className="metric-foot">
            <span>Splunk / Elastic / Sentinel</span>
          </div>
        </div>

        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>Full State Payload</span>
            <Database className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono text-sm uppercase">
            .JSON Format
          </div>
          <div className="metric-foot">
            <span>Deterministic state &amp; trace</span>
          </div>
        </div>
      </div>

      {/* 3. Exportable Investigations Table */}
      <section className="workflows-section">
        <div className="section-heading">
          <div>
            <h2>Exportable Investigation Records</h2>
          </div>
          <span className="text-xs font-mono text-muted-foreground">
            {total} dossiers available
          </span>
        </div>

        <div className="workflow-table-section">
          <div className="table-scroll">
            <table className="workflow-table">
              <thead>
                <tr>
                  <th>Investigation ID</th>
                  <th>Target / Subject</th>
                  <th>Verdict Rating</th>
                  <th>Score</th>
                  <th>Verified Evidence</th>
                  <th className="min-w-[240px]">Download Dossiers</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((inv) => (
                  <tr key={inv.id} className="hover:bg-muted/30 transition">
                    <td className="font-mono text-xs font-semibold text-foreground">
                      <Link href={`/investigations/${inv.id}`} className="hover:underline">
                        {inv.id}
                      </Link>
                    </td>
                    <td className="text-xs text-muted-foreground max-w-sm truncate">
                      {inv.email_metadata?.subject || inv.input_type || 'Intake Scan'}
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
                    <td className="font-mono text-xs text-muted-foreground">
                      {inv.evidence?.length || 0} findings
                    </td>
                    <td>
                      <div className="dossier-actions">
                        <button
                          type="button"
                          onClick={() => generateInvestigationPdf(inv)}
                          className="dossier-btn dossier-btn-pdf"
                          title="Generate & Download Executive PDF Dossier"
                        >
                          <Download className="w-3 h-3 text-red-600 shrink-0" />
                          <span>PDF</span>
                        </button>
                        <a
                          href={getExportDownloadUrl(inv.id, 'md')}
                          download
                          className="dossier-btn"
                          title="Download Markdown Report"
                        >
                          <Download className="w-3 h-3 shrink-0" />
                          <span>MD</span>
                        </a>
                        <a
                          href={getExportDownloadUrl(inv.id, 'csv')}
                          download
                          className="dossier-btn"
                          title="Download CSV for SIEM"
                        >
                          <Download className="w-3 h-3 shrink-0" />
                          <span>CSV</span>
                        </a>
                        <a
                          href={getExportDownloadUrl(inv.id, 'json')}
                          download
                          className="dossier-btn"
                          title="Download Full JSON Payload"
                        >
                          <Download className="w-3 h-3 shrink-0" />
                          <span>JSON</span>
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {investigations.length === 0 && (
              <div className="empty-state py-12 text-center text-xs text-muted-foreground">
                No investigation dossiers available for export. Run an investigation first.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 4. Privacy & Compliance Disclosure */}
      <div className="review-notice p-4 rounded border border-border bg-card text-xs space-y-1">
        <strong className="text-foreground flex items-center gap-1.5 font-semibold">
          <Lock className="w-3.5 h-3.5 text-primary" />
          Enterprise Compliance Notice
        </strong>
        <p className="text-muted-foreground leading-relaxed text-[11px]">
          All exported reports include raw observed indicators, exact regex/rule signatures, and sanitized evidence. Sensitive personally identifiable information (PII) is masked in compliance with SOC 2, HIPAA, and GDPR standards.
        </p>
      </div>
    </div>
  );
}
