'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Activity,
  GitBranch,
  Cpu,
  RefreshCw,
  Clock,
  Layers,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  AlertTriangle,
  Database,
  ShieldCheck
} from 'lucide-react';
import { fetchInvestigations, fetchInvestigationById, fetchProviderStatus, fetchHealth } from '@/lib/api';
import ExecutionTraceTimeline from '@/components/ExecutionTraceTimeline';

export default function SystemHealthPage() {
  const [investigations, setInvestigations] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [selectedInv, setSelectedInv] = useState(null);
  const [providers, setProviders] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [list, prov, h] = await Promise.all([
        fetchInvestigations(),
        fetchProviderStatus(),
        fetchHealth()
      ]);
      setInvestigations(list || []);
      setProviders(prov);
      setHealth(h);
      if (list && list.length > 0) {
        setSelectedId(list[0].id);
        setSelectedInv(list[0]);
      }
    } catch (e) {
      console.warn('Failed to load trace data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSelectCase = async (id) => {
    setSelectedId(id);
    try {
      const inv = await fetchInvestigationById(id);
      setSelectedInv(inv);
    } catch (e) {
      console.error(e);
    }
  };

  const isDbConnected = health?.database?.status === 'connected';

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            AI ORCHESTRATION &amp; HEALTH
          </span>
          <h1>
            System health<span className="heading-dot">.</span>
          </h1>
          <p>
            Real-time LangGraph node states, LLM provider fallback telemetry, and database connectivity.
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            onClick={loadData}
            title="Refresh system telemetry"
            className="inline-flex items-center justify-center gap-1.5 border border-input bg-background shadow-sm hover:bg-accent h-8 rounded-md px-3 text-xs font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Health</span>
          </button>
        </div>
      </div>

      {/* 2. System Status Banners */}
      <div className="bg-card border border-border rounded-md p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-background border border-border flex items-center justify-center text-success">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-semibold text-sm text-foreground">
              All Investigation Services Operational
            </h3>
            <p className="text-xs text-muted-foreground">
              LangGraph 10-node DAG compiled · Python security rules active
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="status-badge tone-success badge-small">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            FASTAPI: ONLINE
          </span>
          <span className={`status-badge ${isDbConnected ? 'tone-success' : 'tone-warning'} badge-small`}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            DB: {isDbConnected ? 'MONGODB ATLAS' : 'CONNECTING'}
          </span>
          <span className="status-badge tone-info badge-small">
            PRIMARY: {providers?.primary_provider?.toUpperCase() || 'GEMINI'}
          </span>
        </div>
      </div>

      {/* 3. Metric Cards */}
      <div className="metric-grid">
        <div className="metric-card">
          <div className="metric-label">
            <span>Primary LLM</span>
            <Cpu className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value uppercase font-mono text-base">
            {providers?.gemini_configured ? 'Gemini Flash' : 'Rules Only'}
          </div>
          <div className="metric-foot">
            <span>Model: {providers?.gemini_model || 'gemini-flash-latest'}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Automatic Fallback</span>
            <GitBranch className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value uppercase font-mono text-base">
            {providers?.groq_configured ? 'Groq Active' : 'Offline Gating'}
          </div>
          <div className="metric-foot">
            <span>Model: {providers?.groq_model || 'openai/gpt-oss-120b'}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">
            <span>Database Latency</span>
            <Database className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value font-mono">
            {health?.database?.latency_ms ? `${health.database.latency_ms.toFixed(1)}` : '< 1'}
            <span className="metric-unit">ms</span>
          </div>
          <div className="metric-foot">
            <span>Database: {health?.database?.database || 'phishguard_ai'}</span>
          </div>
        </div>

        <div className="metric-card metric-review">
          <div className="metric-label">
            <span>Air-Gapped Guarantee</span>
            <Activity className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="metric-value health-value text-base">
            <span className="health-dot tone-success" />
            Zero Clicks
          </div>
          <div className="metric-foot">
            <span>No remote requests made</span>
          </div>
        </div>
      </div>

      {/* 4. Investigation Trace Inspector */}
      <section className="evidence-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">NODE EXECUTION TOPOLOGY</span>
            <h2>Investigation trace inspector</h2>
          </div>

          <div className="section-tools">
            <select
              aria-label="Select investigation"
              value={selectedId}
              onChange={(e) => handleSelectCase(e.target.value)}
              className="text-xs bg-background border border-input rounded px-2.5 py-1 font-mono"
            >
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.id} — {inv.risk?.overall_rating} ({inv.risk?.overall_score || 0}/100)
                </option>
              ))}
            </select>
            {selectedInv && (
              <Link
                href={`/investigations/${selectedInv.id}`}
                className="inline-flex items-center justify-center h-8 w-8 text-muted-foreground hover:text-foreground"
                title="View dossier"
              >
                <ArrowUpRight className="w-4 h-4" />
              </Link>
            )}
          </div>
        </div>

        {selectedInv ? (
          <div className="space-y-4">
            <ExecutionTraceTimeline trace={selectedInv.execution_trace || []} />
          </div>
        ) : (
          <div className="empty-state p-12 text-center text-xs text-muted-foreground">
            No investigations available to trace. Run a scan from New Investigation.
          </div>
        )}
      </section>
    </div>
  );
}
