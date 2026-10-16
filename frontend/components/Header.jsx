'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Shield, Activity, Sparkles, Cpu, Plus, Database, LogIn, LogOut, User, Lock } from 'lucide-react';
import { fetchHealth, fetchProviderStatus } from '@/lib/api';
import { useAuth } from '@/components/AuthProvider';

export default function Header() {
  const { user, logout, loading: authLoading } = useAuth();
  const [health, setHealth] = useState({ status: 'checking' });
  const [providers, setProviders] = useState(null);
  const [loading, setLoading] = useState(false);

  const checkStatus = async () => {
    setLoading(true);
    const [h, p] = await Promise.all([fetchHealth(), fetchProviderStatus()]);
    setHealth(h);
    setProviders(p);
    setLoading(false);
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const isDbConnected = health.database?.status === 'connected';

  return (
    <header className="h-16 border-b border-panel-border bg-obsidian-light/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Title */}
      <div className="flex items-center space-x-3">
        <Link href="/overview" className="flex items-center space-x-2 group">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400/60 transition">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-white text-base tracking-wider uppercase">PhishGuard</span>
              <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-acid/20 text-acid border border-acid/30 font-semibold">AI MVP</span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">Agentic Cybersecurity SOC Platform</p>
          </div>
        </Link>
      </div>

      {/* Telemetry and Provider Status Pills */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* Backend health */}
        <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-panel text-xs border border-panel-border">
          <span className={`w-2 h-2 rounded-full ${health.status === 'healthy' ? 'bg-acid animate-pulse' : 'bg-red-500'}`} />
          <span className="text-slate-300 font-mono text-[11px]">
            API: {health.status === 'healthy' ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* MongoDB Atlas status */}
        <div className="hidden xl:flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-panel text-xs border border-panel-border">
          <Database className={`w-3.5 h-3.5 ${isDbConnected ? 'text-emerald-400' : 'text-amber-400'}`} />
          <span className="text-slate-400 text-[11px]">DB:</span>
          <span className={`font-mono text-[11px] font-medium ${isDbConnected ? 'text-emerald-300' : 'text-amber-300'}`}>
            {isDbConnected ? 'MONGODB ATLAS' : 'CONNECTING'}
          </span>
        </div>

        {/* Primary AI Provider */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1 rounded-full bg-panel text-xs border border-panel-border">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400 text-[11px]">Provider:</span>
          <span className="font-mono text-cyan-300 font-semibold text-[11px]">
            {providers?.gemini_configured ? 'GEMINI' : (providers?.groq_configured ? 'GROQ' : 'RULES ONLY')}
          </span>
          {providers?.fallback_ready && (
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
              FALLBACK READY
            </span>
          )}
        </div>

        {/* Quick Launch Button */}
        <Link
          href="/investigate"
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-obsidian font-semibold text-xs transition shadow-glow-cyan"
        >
          <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
          <span className="hidden sm:inline">New Investigation</span>
          <span className="sm:hidden">Scan</span>
        </Link>

        {/* User Auth Section */}
        {authLoading ? (
          <div className="w-8 h-8 rounded-full bg-panel border border-panel-border animate-pulse" />
        ) : user ? (
          <div className="flex items-center space-x-2 pl-2 border-l border-panel-border">
            <Link
              href="/settings/security"
              className="flex items-center space-x-2 px-2.5 py-1 rounded-lg bg-panel hover:bg-panel-hover border border-panel-border transition"
              title="Account Security & Password Settings"
            >
              <div className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-bold uppercase">
                {user.name ? user.name[0] : 'U'}
              </div>
              <div className="hidden lg:block text-left">
                <p className="text-xs font-medium text-slate-200 leading-none">{user.name}</p>
                <span className="text-[9px] font-mono text-cyan-400 uppercase">{user.role}</span>
              </div>
            </Link>
            <button
              onClick={() => logout()}
              className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/30 transition"
              title="Log out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center space-x-2 pl-2 border-l border-panel-border">
            <Link
              href="/login"
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-panel hover:bg-panel-hover text-slate-200 border border-panel-border text-xs font-medium transition"
            >
              <LogIn className="w-3.5 h-3.5 text-cyan-400" />
              <span>Sign In</span>
            </Link>
            <Link
              href="/register"
              className="hidden sm:flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-700/50 text-xs font-medium transition"
            >
              <span>Register</span>
            </Link>
          </div>
        )}
      </div>
    </header>
  );
}

