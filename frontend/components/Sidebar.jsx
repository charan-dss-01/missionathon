'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldAlert,
  History,
  CheckSquare,
  GitBranch,
  FileText,
  Terminal,
  ExternalLink,
  Lock,
  KeyRound
} from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Overview Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'New Investigation', href: '/investigate', icon: ShieldAlert },
  { name: 'Investigation History', href: '/history', icon: History },
  { name: 'Human Review Queue', href: '/queue', icon: CheckSquare },
  { name: 'Agent Orchestration', href: '/trace', icon: GitBranch },
  { name: 'Reports & Export', href: '/reports', icon: FileText },
  { name: 'Security & Account', href: '/settings/security', icon: KeyRound },
];


export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 border-r border-panel-border bg-obsidian-light/60 flex flex-col justify-between h-[calc(100vh-4rem)] sticky top-16 z-20">
      <div className="py-4">
        {/* Navigation Section */}
        <div className="px-3 mb-2">
          <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold px-3 py-1">
            Operations Center
          </p>
        </div>

        <nav className="space-y-1 px-3">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-panel-hover'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Workflow Specs info */}
        <div className="mt-8 px-4">
          <div className="p-3 rounded-lg bg-panel border border-panel-border text-[11px] space-y-1.5">
            <div className="flex items-center space-x-1.5 text-cyan-400 font-semibold font-mono text-[10px] uppercase">
              <Terminal className="w-3.5 h-3.5" />
              <span>LangGraph Nodes</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              10 explicit nodes with Gemini primary, Groq fallback, & deterministic rule gating.
            </p>
            <div className="pt-1 flex items-center space-x-1 text-[10px] text-acid font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-acid animate-ping" />
              <span>Zero external clicks</span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-panel-border space-y-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center space-x-1">
            <Lock className="w-3 h-3 text-slate-400" />
            <span>Air-Gapped Parsing</span>
          </span>
          <span className="font-mono text-[10px] text-slate-400">v1.0-MVP</span>
        </div>
      </div>
    </aside>
  );
}
