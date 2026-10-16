'use client';

import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  ChevronRight,
  ChevronDown,
  Cpu,
  Layers,
  FileSearch,
  Sliders,
  Sparkles,
  ShieldCheck,
  FileCheck,
  Activity
} from 'lucide-react';

const NODE_ICONS = {
  parse_input: FileSearch,
  analyze_headers: Sliders,
  analyze_body: Layers,
  analyze_urls: FileSearch,
  analyze_attachments: FileSearch,
  aggregate_evidence: Layers,
  calculate_risk: Sliders,
  interpret_with_llm: Sparkles,
  validate_evidence: ShieldCheck,
  generate_report: FileCheck
};

export default function ExecutionTraceTimeline({ trace = [] }) {
  const [expandedNodes, setExpandedNodes] = useState({});

  const toggleExpand = (idx) => {
    setExpandedNodes((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const totalDurationMs = trace.reduce(
    (acc, step) => acc + (step.duration_ms || 0),
    0
  );

  if (!trace || trace.length === 0) {
    return (
      <div className="p-8 border border-border bg-card rounded-md text-center text-xs text-muted-foreground">
        No execution trace recorded for this investigation.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Trace Summary Bar */}
      <div className="flex items-center justify-between p-3.5 rounded-md bg-card border border-border text-xs">
        <div className="flex items-center gap-2 font-mono">
          <span className="text-muted-foreground">Graph Nodes Executed:</span>
          <span className="text-foreground font-bold">{trace.length} Steps</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <Clock className="w-3.5 h-3.5 text-primary" />
          <span className="text-muted-foreground">Pipeline Latency:</span>
          <span className="text-foreground font-bold">{totalDurationMs.toFixed(1)} ms</span>
        </div>
      </div>

      {/* Nodes list */}
      <div className="divide-y divide-border border border-border rounded-md bg-card overflow-hidden">
        {trace.map((step, idx) => {
          const nodeKey = step.node || step.node_name || 'step';
          const nodeTitle = step.name || step.node || step.node_name || 'Node Step';
          const nodeSummary = step.message || step.summary || 'Node execution complete';
          const dataSummary = step.data_summary || step.output_summary;
          const Icon = NODE_ICONS[nodeKey] || Activity;
          const isExpanded = !!expandedNodes[idx];
          const isPassed = step.status === 'COMPLETED' || step.status === 'SUCCESS';

          return (
            <div key={`${nodeKey}-${idx}`} className="transition hover:bg-muted/30">
              <div
                onClick={() => toggleExpand(idx)}
                className="p-3.5 flex items-center justify-between cursor-pointer text-xs"
              >
                <div className="flex items-center gap-3">
                  <div className="w-6 h-6 rounded flex items-center justify-center bg-background border border-border text-primary font-mono text-[10px] font-bold">
                    0{idx + 1}
                  </div>
                  <Icon className="w-4 h-4 text-muted-foreground" />
                  <div>
                    <span className="font-semibold text-foreground mr-2 font-mono">
                      {nodeTitle}
                    </span>
                    <span className="text-muted-foreground text-[11px]">
                      {nodeSummary}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-3 font-mono text-[11px]">
                  <span className="text-muted-foreground">
                    {step.duration_ms ? `${step.duration_ms.toFixed(1)} ms` : '< 1 ms'}
                  </span>
                  <span
                    className={`status-badge ${
                      isPassed ? 'tone-success' : 'tone-danger'
                    } badge-small`}
                  >
                    {step.status || 'COMPLETED'}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  )}
                </div>
              </div>

              {isExpanded && dataSummary && (
                <div className="px-4 pb-3.5 pt-1 text-xs text-muted-foreground bg-background border-t border-border">
                  <span className="text-[10px] font-mono text-muted-foreground uppercase block mb-1">
                    Node Observation Telemetry:
                  </span>
                  <pre className="p-2.5 rounded bg-card border border-border text-[11px] font-mono overflow-x-auto text-foreground">
                    {typeof dataSummary === 'object'
                      ? JSON.stringify(dataSummary, null, 2)
                      : String(dataSummary)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
