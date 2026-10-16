'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Shield } from 'lucide-react';

export default function RiskScoreBadge({ score = 0, rating = 'LOW', coverage = 'FULL', size = 'md' }) {
  const isHigh = score >= 60 || rating === 'HIGH';
  const isMed = (score >= 30 && score < 60) || rating === 'MEDIUM';

  const tone = isHigh ? 'tone-danger' : isMed ? 'tone-warning' : 'tone-success';
  const label = isHigh ? 'HIGH RISK' : isMed ? 'SUSPICIOUS' : 'LOW RISK';
  const Icon = isHigh ? ShieldAlert : isMed ? AlertTriangle : ShieldCheck;

  if (size === 'sm') {
    return (
      <span className={`status-badge ${tone} badge-small font-mono`}>
        <Icon className="w-3 h-3 inline mr-1" />
        <span>{score}/100 {label}</span>
      </span>
    );
  }

  return (
    <div className="bg-card border border-border rounded-md p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="flex items-center gap-3">
        <div className={`p-2.5 rounded-md border border-border bg-background`}>
          <Icon className={`w-6 h-6 ${isHigh ? 'text-danger' : isMed ? 'text-warning' : 'text-success'}`} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl font-bold font-mono tracking-tight text-foreground">
              {score}
            </span>
            <span className="text-muted-foreground text-xs font-mono">/100</span>
            <span className={`status-badge ${tone} badge-small uppercase font-mono`}>
              {label}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            {isHigh && 'Critical threat indicators verified by deterministic Python security rules.'}
            {isMed && 'Elevated heuristic signals detected; manual review recommended.'}
            {!isHigh && !isMed && 'No malicious patterns observed in air-gapped static inspection.'}
          </p>
        </div>
      </div>

      {coverage && (
        <div className="text-left sm:text-right pt-2 sm:pt-0 border-t sm:border-t-0 border-border">
          <span className="text-[10px] text-muted-foreground uppercase font-mono block">
            Analysis Coverage
          </span>
          <span className={`text-xs font-mono font-semibold ${coverage === 'FULL' ? 'text-emerald-600' : 'text-amber-600'}`}>
            {coverage}
          </span>
        </div>
      )}
    </div>
  );
}
