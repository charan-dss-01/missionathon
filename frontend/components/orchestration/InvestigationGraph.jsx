'use client';

import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import {
  STAGE_DEFINITIONS,
  ORCHESTRATOR_CONFIG,
  STAGE_SEQUENCE_EDGES,
} from './orchestrationConfig';
import OrchestratorNode from './OrchestratorNode';
import InvestigationStageNode from './InvestigationStageNode';
import AnimatedEvidenceEdge from './AnimatedEvidenceEdge';
import NodeDetailsPanel from './NodeDetailsPanel';
import { Shield, Activity, RefreshCw } from 'lucide-react';

const nodeTypes = {
  orchestrator: OrchestratorNode,
  stage: InvestigationStageNode,
};

const edgeTypes = {
  animatedEvidence: AnimatedEvidenceEdge,
};

export default function InvestigationGraph({
  trace = [],
  activeNode = null,
  status = 'idle', // 'idle' | 'running' | 'completed' | 'failed'
  result = null,
  compact = false,
  onReset = null,
}) {
  const [selectedNodeId, setSelectedNodeId] = useState(null);

  const handleSelectNode = useCallback((id) => {
    setSelectedNodeId((prev) => (prev === id ? null : id));
  }, []);

  // Compute map of stage data from trace and activeNode
  const stageDataMap = useMemo(() => {
    const map = {};

    // Initialize all 10 stages as PENDING
    STAGE_DEFINITIONS.forEach((s) => {
      map[s.id] = {
        ...s,
        status: 'PENDING',
        duration_ms: null,
        finding_count: 0,
        summary: s.description,
        data_summary: {},
      };
    });

    // Populate from real trace steps
    if (Array.isArray(trace)) {
      trace.forEach((step) => {
        if (!step) return;
        const nodeId = step.node || step.node_name;
        if (map[nodeId]) {
          const stepStatus = step.status?.value || step.status || 'COMPLETED';
          const dataSummary = step.data_summary || {};
          let findingCount = dataSummary.indicators
            ?? dataSummary.total_findings
            ?? dataSummary.findings_count
            ?? dataSummary.attachments_count
            ?? 0;

          map[nodeId] = {
            ...map[nodeId],
            status: String(stepStatus).toUpperCase(),
            duration_ms: step.duration_ms,
            finding_count: findingCount,
            summary: step.message || step.summary || map[nodeId].description,
            data_summary: dataSummary,
          };
        }
      });
    }

    // Set currently active running stage
    if (activeNode && map[activeNode] && status === 'running') {
      map[activeNode].status = 'RUNNING';
    }

    return map;
  }, [trace, activeNode, status]);

  // Compute total authoritative findings count
  const totalFindingsCount = useMemo(() => {
    if (result?.evidence) return result.evidence.length;
    let count = 0;
    Object.values(stageDataMap).forEach((s) => {
      if (s.finding_count && typeof s.finding_count === 'number') {
        count += s.finding_count;
      }
    });
    return count;
  }, [result, stageDataMap]);

  // Compute active stage label for orchestrator
  const activeStageLabel = useMemo(() => {
    if (status === 'running') {
      if (activeNode) {
        const found = STAGE_DEFINITIONS.find((s) => s.id === activeNode);
        return found ? `Active: ${found.name}` : 'Executing node...';
      }
      return 'Orchestrating...';
    }
    if (status === 'completed') return 'All 10 Stages Completed';
    if (status === 'failed') return 'Pipeline Exception';
    return 'Pipeline Standby';
  }, [status, activeNode]);

  // Build React Flow nodes
  const nodes = useMemo(() => {
    const list = [];

    // Central Orchestrator Node
    list.push({
      id: ORCHESTRATOR_CONFIG.id,
      type: 'orchestrator',
      position: ORCHESTRATOR_CONFIG.position,
      data: {
        status,
        evidenceCount: totalFindingsCount,
        activeStageLabel,
        onSelect: handleSelectNode,
      },
      selected: selectedNodeId === 'orchestrator',
    });

    // 10 Surrounding Stage Cards
    STAGE_DEFINITIONS.forEach((s) => {
      const live = stageDataMap[s.id] || {};
      list.push({
        id: s.id,
        type: 'stage',
        position: s.position,
        data: {
          ...s,
          ...live,
          onSelect: handleSelectNode,
        },
        selected: selectedNodeId === s.id,
      });
    });

    return list;
  }, [stageDataMap, status, totalFindingsCount, activeStageLabel, selectedNodeId, handleSelectNode]);

  // Build React Flow edges
  const edges = useMemo(() => {
    const list = [];

    // 1. Linear Pipeline Sequence Edges (Horseshoe flow)
    STAGE_SEQUENCE_EDGES.forEach((edge, idx) => {
      const srcStatus = (stageDataMap[edge.source]?.status || 'PENDING').toLowerCase();
      const tgtStatus = (stageDataMap[edge.target]?.status || 'PENDING').toLowerCase();

      let edgeStatus = 'pending';
      if (tgtStatus === 'running' || (srcStatus === 'running' && tgtStatus === 'pending')) {
        edgeStatus = 'running';
      } else if (srcStatus === 'completed' && tgtStatus === 'completed') {
        edgeStatus = 'completed';
      } else if (srcStatus === 'skipped' || tgtStatus === 'skipped') {
        edgeStatus = 'skipped';
      } else if (srcStatus === 'failed' || tgtStatus === 'failed') {
        edgeStatus = 'failed';
      }

      // Map handles along the horseshoe curve
      let sourceHandle = 'b-src';
      let targetHandle = 't';

      if (edge.source === 'analyze_urls') {
        sourceHandle = 'r-src';
        targetHandle = 'l';
      } else if (edge.source === 'analyze_attachments') {
        sourceHandle = 'r-src';
        targetHandle = 'l';
      } else if (edge.source === 'aggregate_evidence') {
        sourceHandle = 'r-src';
        targetHandle = 'b';
      } else if (edge.source === 'calculate_risk' || edge.source === 'interpret_with_llm' || edge.source === 'validate_evidence') {
        sourceHandle = 't-src';
        targetHandle = 'b';
      }

      list.push({
        id: `seq-${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target,
        sourceHandle,
        targetHandle,
        type: 'animatedEvidence',
        data: { status: edgeStatus },
      });
    });

    // 2. Subtle Radial Orchestrator Link Edges
    STAGE_DEFINITIONS.forEach((s) => {
      const sStatus = (stageDataMap[s.id]?.status || 'PENDING').toLowerCase();
      const isRadialActive = sStatus === 'running' || sStatus === 'completed';

      list.push({
        id: `radial-orch-${s.id}`,
        source: ORCHESTRATOR_CONFIG.id,
        target: s.id,
        type: 'animatedEvidence',
        data: {
          status: isRadialActive ? (sStatus === 'running' ? 'running' : 'completed') : 'pending',
        },
        style: {
          opacity: isRadialActive ? 0.35 : 0.12,
          strokeDasharray: '2 6',
        },
      });
    });

    return list;
  }, [stageDataMap]);

  return (
    <div className={`relative w-full rounded-lg border border-border bg-card overflow-hidden shadow-sm ${compact ? 'h-[460px]' : 'h-[640px]'}`}>
      {/* Top Telemetry Header Bar */}
      <div className="absolute top-0 inset-x-0 h-10 px-4 border-b border-border bg-background/80 backdrop-blur-sm z-10 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-primary" />
          <span className="font-semibold text-foreground tracking-tight">
            Live Investigation Orchestration Graph
          </span>
          <span className="text-muted-foreground">·</span>
          <span className="text-[10px] font-mono text-muted-foreground uppercase">
            LangGraph 10-Node Topology
          </span>
        </div>

        {/* Legend Indicators */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
            <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
            <span>RUNNING</span>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>COMPLETED</span>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            <span>SKIPPED</span>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
            <span className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-700" />
            <span>PENDING</span>
          </div>
        </div>
      </div>

      {/* React Flow Viewport */}
      <div className="w-full h-full pt-10">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.4}
          maxZoom={1.5}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={true}
          proOptions={{ hideAttribution: true }}
        >
          <Background
            variant="lines"
            gap={28}
            size={1}
            color="rgba(148, 163, 184, 0.12)"
          />
          <Controls
            showInteractive={false}
            position="bottom-left"
            className="!bg-card !border-border !shadow-sm !rounded !overflow-hidden [&>button]:!border-border [&>button]:!bg-background [&>button]:!text-foreground [&>button:hover]:!bg-accent"
          />
        </ReactFlow>
      </div>

      {/* Interactive Stage / Orchestrator Details Drawer */}
      <NodeDetailsPanel
        selectedId={selectedNodeId}
        stageData={stageDataMap}
        result={result}
        onClose={() => setSelectedNodeId(null)}
        onSelectNode={(id) => setSelectedNodeId(id)}
      />

      {/* Bottom Status / Summary Footer */}
      <div className="absolute bottom-0 inset-x-0 h-8 px-4 border-t border-border bg-background/80 backdrop-blur-sm z-10 flex items-center justify-between text-[11px] text-muted-foreground">
        <div className="flex items-center gap-2">
          <Activity className="w-3 h-3 text-primary" />
          <span className="font-mono text-[10px]">
            {status === 'running'
              ? 'Real-time telemetry stream active · Zero external HTTP queries'
              : status === 'completed'
              ? `Investigation complete · ${result?.risk?.overall_rating || 'EVALUATED'} (${result?.risk?.overall_score || 0}/100)`
              : 'Air-gapped static execution pipeline ready'}
          </span>
        </div>

        <div className="text-[10px] font-mono">
          Click any card for execution telemetry &amp; evidence
        </div>
      </div>
    </div>
  );
}
