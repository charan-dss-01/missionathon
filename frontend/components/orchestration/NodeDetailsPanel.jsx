'use client';

import React from 'react';
import {
  X,
  Clock,
  CheckCircle2,
  AlertTriangle,
  SkipForward,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
  FileText,
  Activity,
  Sparkles,
  Info
} from 'lucide-react';
import { STAGE_DEFINITIONS, STATUS_COLORS } from './orchestrationConfig';

export default function NodeDetailsPanel({
  selectedId,
  stageData,
  result,
  onClose,
  onSelectNode,
}) {
  if (!selectedId) return null;

  const isOrchestrator = selectedId === 'orchestrator';

  // Find stage definition and current runtime data
  const stageDefIndex = STAGE_DEFINITIONS.findIndex((s) => s.id === selectedId);
  const stageDef = stageDefIndex !== -1 ? STAGE_DEFINITIONS[stageDefIndex] : null;
  const currentStage = stageData?.[selectedId] || stageDef || {};

  const status = (currentStage.status || 'PENDING').toUpperCase();
  const colors = STATUS_COLORS[status] || STATUS_COLORS.PENDING;

  // Previous / Next stage navigation
  const prevStage = stageDefIndex > 0 ? STAGE_DEFINITIONS[stageDefIndex - 1] : null;
  const nextStage = stageDefIndex !== -1 && stageDefIndex < STAGE_DEFINITIONS.length - 1
    ? STAGE_DEFINITIONS[stageDefIndex + 1]
    : null;

  // Find evidence records associated with this stage
  let stageEvidence = [];
  if (result?.evidence && stageDef) {
    stageEvidence = result.evidence.filter((ev) => {
      const loc = (ev.source_location || '').toLowerCase();
      const cat = (ev.category || '').toLowerCase();
      const rule = (ev.rule_id || '').toLowerCase();

      if (selectedId === 'analyze_headers') {
        return cat.includes('auth') || cat.includes('header') || loc.includes('header') || rule.startsWith('hdr_') || rule.startsWith('auth_');
      }
      if (selectedId === 'analyze_body') {
        return cat.includes('body') || loc.includes('body') || rule.startsWith('body_');
      }
      if (selectedId === 'analyze_urls') {
        return cat.includes('url') || loc.includes('url') || loc.includes('anchor') || rule.startsWith('url_');
      }
      if (selectedId === 'analyze_attachments') {
        return cat.includes('attachment') || cat.includes('payload') || loc.includes('attachment') || loc.includes('archive') || rule.startsWith('att_');
      }
      return false;
    });
  }

  // Duration formatting
  let durationText = '—';
  if (currentStage.duration_ms !== undefined && currentStage.duration_ms !== null) {
    durationText = currentStage.duration_ms < 1000
      ? `${Math.round(currentStage.duration_ms)} ms`
      : `${(currentStage.duration_ms / 1000).toFixed(2)} s`;
  }

  return (
    <div
      className="node-details-panel animate-in fade-in slide-in-from-right-4 duration-200"
      style={{ backgroundColor: '#ffffff', zIndex: 50 }}
    >
      {/* Panel Header */}
      <div className="panel-header">
        <div className="flex items-center gap-2">
          {isOrchestrator ? (
            <Shield className="w-4 h-4 text-primary" />
          ) : (
            <Activity className="w-4 h-4 text-primary" />
          )}
          <span className="text-xs font-semibold text-foreground tracking-tight">
            {isOrchestrator ? 'Orchestrator Telemetry' : 'Stage Execution Record'}
          </span>
        </div>
        <button
          onClick={onClose}
          className="w-6 h-6 rounded flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-slate-200 transition cursor-pointer"
          aria-label="Close details"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Panel Scrollable Body */}
      <div className="panel-body space-y-4 text-xs">
        {isOrchestrator ? (
          /* Orchestrator View */
          <>
            <div>
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider block mb-1">
                COORDINATION HUB
              </span>
              <h3 className="text-base font-semibold text-foreground">
                PhishGuard Central Orchestrator
              </h3>
              <p className="text-muted-foreground text-[11px] mt-1 leading-relaxed">
                Stateful coordinator managing the 10-node LangGraph investigation pipeline. Enforces strict linear validation, deterministic Python security rules, and air-gapped guarantees.
              </p>
            </div>

            <div className="panel-subcard p-3 space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">Pipeline State:</span>
                <span className="font-mono font-medium uppercase text-foreground">
                  {stageData?.orchestrator?.status || 'Active'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">Authoritative Findings:</span>
                <span className="font-mono font-semibold text-primary">
                  {result?.evidence?.length ?? stageData?.orchestrator?.evidenceCount ?? 0}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">Overall Risk Assessment:</span>
                <span className="font-mono font-semibold text-foreground">
                  {result?.risk?.overall_score ?? '—'}/100 ({result?.risk?.overall_rating || 'EVALUATING'})
                </span>
              </div>
            </div>

            <div>
              <h4 className="text-[11px] font-semibold text-foreground mb-2">
                Pipeline Stage Sequence (10 Nodes)
              </h4>
              <div className="space-y-1.5">
                {STAGE_DEFINITIONS.map((s, idx) => {
                  const sStatus = (stageData?.[s.id]?.status || 'PENDING').toUpperCase();
                  const sColor = STATUS_COLORS[sStatus] || STATUS_COLORS.PENDING;
                  return (
                    <button
                      key={s.id}
                      onClick={() => onSelectNode?.(s.id)}
                      className="w-full p-2 rounded border border-border/80 bg-background hover:bg-slate-100 text-left flex items-center justify-between transition cursor-pointer"
                    >
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {s.stepNumber} · {s.name}
                      </span>
                      <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded border ${sColor.badge}`}>
                        {sStatus}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </>
        ) : (
          /* Individual Stage View */
          <>
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-wider font-semibold">
                  STAGE {stageDef?.stepNumber} · {stageDef?.category}
                </span>
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-mono font-medium border ${colors.badge}`}>
                  {status}
                </span>
              </div>
              <h3 className="text-sm font-semibold text-foreground">
                {stageDef?.fullName || currentStage.name}
              </h3>
              <p className="text-muted-foreground text-[11px] mt-1 leading-snug">
                {stageDef?.description}
              </p>
            </div>

            {/* Performance & Finding Metrics */}
            <div className="grid grid-cols-2 gap-2">
              <div className="panel-subcard p-2.5">
                <span className="text-[9px] text-muted-foreground block font-medium">Execution Duration</span>
                <strong className="text-sm font-mono text-foreground mt-0.5 block">
                  {durationText}
                </strong>
              </div>
              <div className="panel-subcard p-2.5">
                <span className="text-[9px] text-muted-foreground block font-medium">Findings Recorded</span>
                <strong className="text-sm font-mono text-foreground mt-0.5 block">
                  {currentStage.finding_count ?? stageEvidence.length ?? 0}
                </strong>
              </div>
            </div>

            {/* Execution Summary */}
            <div className="panel-subcard p-3 space-y-1.5">
              <span className="text-[10px] font-mono text-muted-foreground uppercase font-semibold block">
                Execution Output Summary
              </span>
              <p className="text-[11px] text-foreground leading-relaxed">
                {currentStage.summary || (status === 'PENDING' ? 'Awaiting upstream node completion.' : 'Completed without notes.')}
              </p>
            </div>

            {/* Data Summary Key-Values */}
            {currentStage.data_summary && Object.keys(currentStage.data_summary).length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono text-muted-foreground uppercase font-semibold block">
                  Telemetry Metadata
                </span>
                <div className="panel-subcard p-2.5 font-mono text-[10px] space-y-1">
                  {Object.entries(currentStage.data_summary).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground truncate">{k}:</span>
                      <span className="text-foreground truncate font-medium">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Stage-Contributed Evidence Findings */}
            {stageEvidence.length > 0 && (
              <div className="space-y-2">
                <span className="text-[10px] font-mono text-muted-foreground uppercase font-semibold block">
                  Contributing Evidence ({stageEvidence.length})
                </span>
                <div className="space-y-2">
                  {stageEvidence.map((ev, idx) => (
                    <div key={idx} className="panel-subcard p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono text-primary font-semibold">
                          {ev.rule_id}
                        </span>
                        <span className="text-[8px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-200 text-slate-800 font-medium">
                          {ev.severity}
                        </span>
                      </div>
                      <strong className="text-[11px] font-semibold text-foreground block">
                        {ev.title}
                      </strong>
                      <p className="text-[10px] text-muted-foreground leading-snug">
                        {ev.supporting_observation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Panel Footer: Prev / Next Navigation */}
      {!isOrchestrator && (
        <div className="panel-footer">
          <button
            onClick={() => prevStage && onSelectNode?.(prevStage.id)}
            disabled={!prevStage}
            className="inline-flex items-center gap-1 text-[11px] font-medium text-muted-foreground hover:text-foreground disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Prev Stage</span>
          </button>

          <button
            onClick={() => onSelectNode?.('orchestrator')}
            className="text-[10px] font-mono text-primary hover:underline cursor-pointer"
          >
            View Core
          </button>

          <button
            onClick={() => nextStage && onSelectNode?.(nextStage.id)}
            disabled={!nextStage}
            className="inline-flex items-center gap-1 text-[11px] font-medium text-muted-foreground hover:text-foreground disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed"
          >
            <span>Next Stage</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
