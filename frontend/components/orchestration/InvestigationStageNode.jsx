'use client';

import React from 'react';
import { Handle, Position } from '@xyflow/react';
import {
  FileCode,
  ShieldCheck,
  FileText,
  Globe,
  Paperclip,
  Layers,
  Activity,
  Sparkles,
  CheckCheck,
  FileSpreadsheet,
  Check,
  Clock,
  SkipForward,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { STATUS_COLORS } from './orchestrationConfig';

const ICON_MAP = {
  FileCode,
  ShieldCheck,
  FileText,
  Globe,
  Paperclip,
  Layers,
  Activity,
  Sparkles,
  CheckCheck,
  FileSpreadsheet,
};

export default function InvestigationStageNode({ data, selected }) {
  const status = (data.status || 'PENDING').toUpperCase();
  const colors = STATUS_COLORS[status] || STATUS_COLORS.PENDING;
  const isRunning = status === 'RUNNING';
  const isCompleted = status === 'COMPLETED';
  const isSkipped = status === 'SKIPPED';
  const isFailed = status === 'FAILED';

  const IconComponent = ICON_MAP[data.iconName] || Activity;

  // Format duration
  let durationText = '—';
  if (data.duration_ms !== undefined && data.duration_ms !== null) {
    durationText = data.duration_ms < 1000
      ? `${Math.round(data.duration_ms)}ms`
      : `${(data.duration_ms / 1000).toFixed(1)}s`;
  }

  // Finding count display
  let findingText = '—';
  if (isCompleted || isSkipped) {
    const count = data.finding_count ?? 0;
    findingText = `${count} ${count === 1 ? 'finding' : 'findings'}`;
  }

  return (
    <div
      onClick={() => data.onSelect?.(data.id)}
      style={{ backgroundColor: '#ffffff' }}
      className={`investigation-stage-node relative w-[190px] rounded-md border p-2.5 shadow-sm transition-all duration-200 select-none cursor-pointer ${
        colors.border
      } ${isRunning ? 'ring-2 ring-cyan-500/30 shadow-md' : ''} ${
        selected ? 'is-selected ring-2 ring-teal-600 ring-offset-1' : ''
      } hover:shadow-md`}
    >
      {/* Handles for sequence and orchestrator radial edges */}
      <Handle type="target" position={Position.Top} id="t" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="source" position={Position.Top} id="t-src" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="target" position={Position.Bottom} id="b" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="source" position={Position.Bottom} id="b-src" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="target" position={Position.Left} id="l" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="source" position={Position.Left} id="l-src" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="target" position={Position.Right} id="r" className="w-2 h-2 !bg-border border border-card" />
      <Handle type="source" position={Position.Right} id="r-src" className="w-2 h-2 !bg-border border border-card" />

      {/* Top Header: Category Tag & Status Pill */}
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[8px] font-mono font-medium tracking-wider text-muted-foreground uppercase">
          {data.stepNumber} · {data.category}
        </span>
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[8px] font-mono font-medium border ${colors.badge}`}
        >
          {isRunning && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
          {isCompleted && <Check className="w-2.5 h-2.5" />}
          {isSkipped && <SkipForward className="w-2.5 h-2.5" />}
          {isFailed && <AlertCircle className="w-2.5 h-2.5" />}
          {!isRunning && !isCompleted && !isSkipped && !isFailed && <Clock className="w-2.5 h-2.5" />}
          {status}
        </span>
      </div>

      {/* Stage Title and Icon */}
      <div className="flex items-center gap-2 mb-1.5">
        <div
          className={`w-6 h-6 rounded flex items-center justify-center shrink-0 border transition-colors ${
            isRunning
              ? 'bg-cyan-500/15 border-cyan-500/30 text-cyan-600 dark:text-cyan-400'
              : isCompleted
              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
              : isSkipped
              ? 'bg-amber-500/15 border-amber-500/30 text-amber-600 dark:text-amber-400'
              : isFailed
              ? 'bg-rose-500/15 border-rose-500/30 text-rose-600 dark:text-rose-400'
              : 'bg-secondary border-border text-muted-foreground'
          }`}
        >
          <IconComponent className="w-3.5 h-3.5" />
        </div>
        <div className="min-w-0 flex-1">
          <strong className="text-xs font-semibold text-foreground tracking-tight block truncate">
            {data.name}
          </strong>
        </div>
      </div>

      {/* Execution Metrics (Duration & Findings) */}
      <div className="flex items-center justify-between text-[9px] font-mono text-muted-foreground pt-1 border-t border-border/60 mb-1">
        <span>{durationText}</span>
        <span className={findingText !== '—' && findingText !== '0 findings' ? 'text-primary font-medium' : ''}>
          {findingText}
        </span>
      </div>

      {/* Execution Summary / Snippet */}
      <p className="text-[9px] text-muted-foreground line-clamp-1 leading-snug">
        {data.summary || data.description}
      </p>
    </div>
  );
}
