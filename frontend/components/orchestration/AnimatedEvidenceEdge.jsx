'use client';

import React from 'react';
import { BaseEdge, getBezierPath } from '@xyflow/react';

export default function AnimatedEvidenceEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  style = {},
  markerEnd,
}) {
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetPosition,
    targetX,
    targetY,
    curvature: 0.35,
  });

  const status = (data?.status || 'pending').toLowerCase();
  const isRunning = status === 'running';
  const isCompleted = status === 'completed';
  const isSkipped = status === 'skipped';
  const isFailed = status === 'failed';

  // Base stroke styling
  let strokeColor = 'rgba(148, 163, 184, 0.4)'; // slate-400/40
  let strokeWidth = 1.5;
  let strokeDasharray = undefined;

  if (isRunning) {
    strokeColor = 'rgb(6, 182, 212)'; // cyan-500
    strokeWidth = 2;
  } else if (isCompleted) {
    strokeColor = 'rgba(16, 185, 129, 0.6)'; // emerald-500/60
    strokeWidth = 1.5;
  } else if (isSkipped) {
    strokeColor = 'rgba(245, 158, 11, 0.45)'; // amber-500/45
    strokeDasharray = '4 4';
  } else if (isFailed) {
    strokeColor = 'rgba(244, 63, 94, 0.6)'; // rose-500/60
  }

  const customStyle = {
    ...style,
    stroke: strokeColor,
    strokeWidth,
    strokeDasharray,
    transition: 'stroke 0.3s, stroke-width 0.3s',
  };

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={customStyle} markerEnd={markerEnd} />

      {/* High-visibility active particle animation along running edge */}
      {isRunning && (
        <circle r={3.5} fill="#06b6d4" className="shadow-[0_0_8px_#06b6d4]">
          <animateMotion
            dur="1.2s"
            repeatCount="indefinite"
            path={edgePath}
            rotate="auto"
          />
        </circle>
      )}

      {/* Subtle completed signal glow */}
      {isCompleted && (
        <circle r={2} fill="#10b981" opacity={0.6}>
          <animateMotion
            dur="4s"
            repeatCount="indefinite"
            path={edgePath}
            rotate="auto"
          />
        </circle>
      )}
    </>
  );
}
