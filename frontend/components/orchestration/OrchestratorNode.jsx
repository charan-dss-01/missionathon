'use client';

import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { Shield, Cpu, Activity, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

export default function OrchestratorNode({ data, selected }) {
  const status = data.status || 'idle'; // 'idle' | 'running' | 'completed' | 'failed'
  const isRunning = status === 'running';
  const isCompleted = status === 'completed';
  const isFailed = status === 'failed';
  const evidenceCount = data.evidenceCount ?? 0;
  const activeStageLabel = data.activeStageLabel || (isRunning ? 'Executing LangGraph...' : isCompleted ? 'All Stages Evaluated' : 'Awaiting Input');

  return (
    <div
      onClick={() => data.onSelect?.('orchestrator')}
      className={`relative w-52 h-52 rounded-full cursor-pointer select-none flex items-center justify-center transition-all duration-300 ${
        selected ? 'ring-2 ring-primary ring-offset-2' : ''
      }`}
    >
      {/* Target/Source Connection Handles in 4 directions */}
      <Handle type="target" position={Position.Top} id="orch-t" className="opacity-0 pointer-events-none" />
      <Handle type="source" position={Position.Top} id="orch-t-src" className="opacity-0 pointer-events-none" />
      <Handle type="target" position={Position.Bottom} id="orch-b" className="opacity-0 pointer-events-none" />
      <Handle type="source" position={Position.Bottom} id="orch-b-src" className="opacity-0 pointer-events-none" />
      <Handle type="target" position={Position.Left} id="orch-l" className="opacity-0 pointer-events-none" />
      <Handle type="source" position={Position.Left} id="orch-l-src" className="opacity-0 pointer-events-none" />
      <Handle type="target" position={Position.Right} id="orch-r" className="opacity-0 pointer-events-none" />
      <Handle type="source" position={Position.Right} id="orch-r-src" className="opacity-0 pointer-events-none" />

      {/* Outer concentric dashed ring - subtle rotation when running */}
      <div
        className={`absolute -inset-4 rounded-full border border-dashed border-primary/25 pointer-events-none transition-opacity duration-300 ${
          isRunning ? 'animate-[spin_20s_linear_infinite] border-cyan-500/50' : 'opacity-40'
        }`}
      />

      {/* Middle concentric ring with dual-tone gradient accents */}
      <div
        className={`absolute -inset-1.5 rounded-full border pointer-events-none transition-all duration-300 ${
          isRunning
            ? 'border-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
            : isCompleted
            ? 'border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
            : isFailed
            ? 'border-rose-500/50 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
            : 'border-border shadow-sm'
        }`}
      />

      {/* Running pulse aura */}
      {isRunning && (
        <div className="absolute inset-0 rounded-full bg-cyan-500/10 animate-ping pointer-events-none" />
      )}

      {/* Central circular core */}
      <div className="relative w-48 h-48 rounded-full bg-card border border-border shadow-md flex flex-col items-center justify-center p-3 text-center overflow-hidden">
        {/* Subtle radial background glow */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,var(--primary-foreground)_0%,transparent_70%)] opacity-5 pointer-events-none" />

        {/* Top kicker */}
        <span className="text-[8px] font-mono tracking-widest text-primary/80 uppercase font-semibold">
          PHISHGUARD AI
        </span>

        {/* Central Icon */}
        <div className="my-1.5 relative">
          <div
            className={`w-9 h-9 rounded-full flex items-center justify-center transition-colors duration-200 ${
              isRunning
                ? 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-400'
                : isCompleted
                ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                : isFailed
                ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400'
                : 'bg-secondary text-muted-foreground'
            }`}
          >
            {isRunning ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : isCompleted ? (
              <Shield className="w-5 h-5" />
            ) : isFailed ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <Cpu className="w-5 h-5" />
            )}
          </div>
        </div>

        {/* Core title */}
        <strong className="text-xs font-semibold text-foreground tracking-tight">
          Orchestrator Core
        </strong>

        {/* Pipeline status badge */}
        <div className="mt-1">
          {isRunning && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-medium bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
              ORCHESTRATING
            </span>
          )}
          {isCompleted && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-medium bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
              <CheckCircle2 className="w-2.5 h-2.5" />
              EVALUATED
            </span>
          )}
          {isFailed && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-medium bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">
              FAILED
            </span>
          )}
          {!isRunning && !isCompleted && !isFailed && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-medium bg-secondary text-muted-foreground border border-border">
              STANDBY
            </span>
          )}
        </div>

        {/* Findings Counter */}
        <div className="mt-1.5 text-[10px] font-mono font-semibold text-foreground/90">
          {evidenceCount} {evidenceCount === 1 ? 'FINDING' : 'FINDINGS'}
        </div>

        {/* Active Stage or Status Sub-label */}
        <div className="mt-0.5 text-[8px] text-muted-foreground truncate max-w-[150px]">
          {activeStageLabel}
        </div>
      </div>
    </div>
  );
}
