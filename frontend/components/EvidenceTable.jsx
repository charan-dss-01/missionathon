'use client';

import React, { useState } from 'react';
import SeverityBadge from './SeverityBadge';
import { Search, ShieldCheck, Info } from 'lucide-react';

export default function EvidenceTable({ evidence = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  const categories = ['ALL', ...Array.from(new Set(evidence.map((e) => e.category)))];

  const filteredEvidence = evidence.filter((item) => {
    const s = searchTerm.toLowerCase();
    const matchesSearch =
      item.title.toLowerCase().includes(s) ||
      item.rule_id.toLowerCase().includes(s) ||
      (item.supporting_observation || '').toLowerCase().includes(s);
    const matchesCategory =
      selectedCategory === 'ALL' || item.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  if (!evidence || evidence.length === 0) {
    return (
      <div className="empty-state p-8 border border-border bg-card rounded-md text-center space-y-2">
        <ShieldCheck className="w-8 h-8 text-success mx-auto" />
        <strong className="text-sm text-foreground block">
          No Authoritative Threat Evidence Detected
        </strong>
        <p className="text-xs text-muted-foreground max-w-md mx-auto">
          Static header, syntactic URL, and file byte scanners did not discover known attack signatures.
        </p>
      </div>
    );
  }

  return (
    <div className="workflow-table-section">
      {/* Controls Bar */}
      <div className="table-controls">
        <div className="table-tabs">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`table-tab ${selectedCategory === cat ? 'active' : ''}`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="table-search-tools">
          <label className="search-field">
            <Search className="w-3.5 h-3.5 text-muted-foreground" />
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter rules, observations…"
            />
          </label>
        </div>
      </div>

      {/* Table */}
      <div className="table-scroll">
        <table className="workflow-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Category</th>
              <th>Finding &amp; Supporting Observation</th>
              <th>Source Location</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvidence.map((record, idx) => (
              <tr key={`${record.rule_id}-${idx}`} className="hover:bg-muted/30 transition">
                <td className="align-top py-2.5">
                  <SeverityBadge severity={record.severity} />
                </td>
                <td className="align-top py-2.5 font-mono text-xs font-semibold text-primary">
                  {record.rule_id}
                </td>
                <td className="align-top py-2.5 font-mono text-[11px] text-muted-foreground uppercase">
                  {record.category}
                </td>
                <td className="align-top py-2.5 space-y-1 max-w-xl">
                  <p className="font-medium text-foreground text-xs">{record.title}</p>
                  <p className="text-muted-foreground text-[11px] leading-relaxed">
                    {record.description}
                  </p>
                  <div className="p-2 rounded bg-background border border-border text-[11px] font-mono text-foreground">
                    <span className="text-[9px] text-muted-foreground uppercase block mb-0.5 font-sans">
                      Authoritative Observation:
                    </span>
                    {record.supporting_observation}
                  </div>
                  {record.limitations && (
                    <div className="flex items-start gap-1 text-[10px] text-muted-foreground pt-0.5">
                      <Info className="w-3 h-3 shrink-0 mt-0.5 text-muted-foreground" />
                      <span>{record.limitations}</span>
                    </div>
                  )}
                </td>
                <td className="align-top py-2.5 font-mono text-xs text-muted-foreground">
                  {record.source_location || 'Global Input'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
