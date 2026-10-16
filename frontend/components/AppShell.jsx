'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  LayoutDashboard,
  PlusCircle,
  GitBranch,
  ScanSearch,
  UsersRound,
  Activity,
  KeyRound,
  PanelLeftClose,
  PanelLeft,
  ChevronDown,
  HelpCircle,
  ArrowUpRight,
  Search,
  Bell,
  LogOut,
  LogIn
} from 'lucide-react';
import { useAuth } from '@/components/AuthProvider';
import { fetchHealth, fetchProviderStatus, fetchInvestigations } from '@/lib/api';

const NAV_ITEMS = [
  { name: 'Operations Overview', href: '/overview', icon: LayoutDashboard },
  { name: 'New Investigation', href: '/investigate', icon: PlusCircle },
  { name: 'Workflows', href: '/history', icon: GitBranch },
  { name: 'Evidence Explorer', href: '/reports', icon: ScanSearch },
  { name: 'Human Review', href: '/queue', icon: UsersRound, showCount: true },
  { name: 'System Health', href: '/trace', icon: Activity },
  { name: 'Security & Account', href: '/settings/security', icon: KeyRound },
];

export default function AppShell({ children }) {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [health, setHealth] = useState({ status: 'checking' });
  const [providers, setProviders] = useState(null);
  const [reviewCount, setReviewCount] = useState(0);

  const isLandingPage = pathname === '/' || pathname === '/landing';

  const checkTelemetry = async () => {
    try {
      const [h, p, invs] = await Promise.all([
        fetchHealth(),
        fetchProviderStatus(),
        fetchInvestigations({ status: 'NEW' })
      ]);
      setHealth(h);
      setProviders(p);
      if (Array.isArray(invs)) {
        setReviewCount(invs.filter(i => i.review_status === 'NEW' || !i.review_status).length);
      }
    } catch (e) {
      console.warn('Telemetry load error:', e);
    }
  };

  useEffect(() => {
    if (isLandingPage) return;
    checkTelemetry();
    const interval = setInterval(checkTelemetry, 30000);
    return () => clearInterval(interval);
  }, [pathname, isLandingPage]);

  if (isLandingPage) {
    return <>{children}</>;
  }

  const getPageTitle = () => {
    if (pathname === '/overview' || pathname === '/') return 'Operations Overview';
    if (pathname === '/investigate') return 'New Investigation';
    if (pathname.startsWith('/investigations/')) return 'Investigation Dossier';
    if (pathname === '/history') return 'Workflows';
    if (pathname === '/reports') return 'Evidence Explorer';
    if (pathname === '/queue') return 'Human Review';
    if (pathname === '/trace') return 'System Health & Orchestration';
    if (pathname === '/settings/security') return 'Security & Account';
    if (pathname === '/login') return 'Analyst Authentication';
    if (pathname === '/register') return 'Analyst Registration';
    return 'Control Tower';
  };

  const isDbConnected = health.database?.status === 'connected';
  const userInitial = user?.name ? user.name.slice(0, 2).toUpperCase() : 'BR';

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      {/* Reference App Sidebar */}
      <aside className="app-sidebar">
        {/* Brand */}
        <Link className="brand active" href="/overview" title="PhishGuard Control Tower">
          <div className="brand-mark">
            <Shield className="w-6 h-6 stroke-[1.8]" />
          </div>
          <div className="brand-copy">
            <strong>
              PHISHGUARD<span>®</span>
            </strong>
            <small>CONTROL TOWER</small>
          </div>
        </Link>

        {/* Workspace Switcher */}
        <div className="workspace-switch">
          <div className="workspace-avatar">P</div>
          <div className="sidebar-label">
            <strong>Cyber SOC Operations</strong>
            <small>Connected workspace</small>
          </div>
          <ChevronDown className="w-3.5 h-3.5 sidebar-label text-muted-foreground ml-auto" />
        </div>

        {/* Navigation Caption */}
        <div className="nav-caption sidebar-label">WORKSPACE</div>

        {/* Nav Links */}
        <nav>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href ||
              (item.href !== '/' && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`nav-item ${isActive ? 'nav-active active' : ''}`}
                title={item.name}
              >
                <span className="nav-icon-wrap">
                  <Icon className="w-4 h-4 shrink-0" />
                </span>
                <span className="sidebar-label">{item.name}</span>
                {item.showCount && (
                  <span className="nav-count sidebar-label">
                    {reviewCount}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Bottom */}
        <div className="sidebar-bottom">
          <div className="environment sidebar-label">
            <span
              className={`health-dot ${
                isDbConnected ? 'tone-success' : 'tone-warning'
              }`}
            />
            <div>
              <strong>
                {isDbConnected ? 'Atlas DB Active' : 'Local Instance'}
              </strong>
              <small>
                {isDbConnected
                  ? 'MongoDB Atlas live cluster'
                  : 'Backend data local'}
              </small>
            </div>
          </div>

          <Link
            href="/reports"
            className="sidebar-help"
            title="System documentation & integration"
          >
            <span className="nav-icon-wrap">
              <HelpCircle className="w-4 h-4 shrink-0" />
            </span>
            <span className="sidebar-label">Help & integration</span>
            <ArrowUpRight className="w-3.5 h-3.5 sidebar-label ml-auto" />
          </Link>

          <Link href="/settings/security" className="profile" title="Account profile">
            <div className="profile-avatar">{userInitial}</div>
            <div className="sidebar-label">
              <strong>{user ? user.name : 'Bathini Ruthvik'}</strong>
              <small>
                {user ? `${user.role.toUpperCase()} Analyst` : 'Workspace owner'}
              </small>
            </div>
          </Link>
        </div>
      </aside>

      {/* Main Shell */}
      <div className="main-shell">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-left">
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="topbar-btn"
              title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
              aria-label="Toggle navigation"
            >
              {collapsed ? (
                <PanelLeft className="w-4 h-4" />
              ) : (
                <PanelLeftClose className="w-4 h-4" />
              )}
            </button>
            <span className="breadcrumb">
              Workspace <span>/</span> <strong>{getPageTitle()}</strong>
            </span>
          </div>

          <div className="topbar-right">
            <span
              className="example-label"
              title={
                providers?.gemini_configured
                  ? 'Primary LLM: Gemini 1.5 Flash'
                  : providers?.groq_configured
                  ? 'Fallback LLM: Groq Llama 3'
                  : 'Deterministic Rule Engine'
              }
            >
              <span
                className={`health-dot ${
                  providers?.gemini_configured || providers?.groq_configured
                    ? 'tone-success'
                    : 'tone-info'
                } inline-block mr-1.5`}
              />
              {providers?.gemini_configured
                ? 'Telemetry: Active (Gemini)'
                : providers?.groq_configured
                ? 'Telemetry: Active (Groq)'
                : 'Telemetry: Air-Gapped Rules'}
            </span>

            <Link
              href="/history"
              className="topbar-btn"
              title="Search workflows"
              aria-label="Search workflows"
            >
              <Search className="w-4 h-4" />
            </Link>

            <Link
              href="/queue"
              className="topbar-btn relative"
              title="Recent alerts & review queue"
              aria-label="Recent alerts & review queue"
            >
              <Bell className="w-4 h-4" />
              {reviewCount > 0 && (
                <span className="notification-badge" />
              )}
            </Link>

            {user ? (
              <button
                onClick={() => logout()}
                className="topbar-auth-btn text-muted-foreground hover:text-danger"
                title="Sign Out"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            ) : (
              <Link
                href="/login"
                className="topbar-auth-btn"
                title="Sign In"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </Link>
            )}

            <Link href="/settings/security" title={`Account: ${user ? user.name : 'Analyst'}`} className="shrink-0">
              <div className="top-avatar">{userInitial}</div>
            </Link>
          </div>
        </header>

        {/* Workspace Main */}
        <main className="workspace-main">{children}</main>

        {/* Reference Footer */}
        <footer className="app-footer">
          <span>
            <Shield className="w-3 h-3 inline-block mr-1.5" />
            PHISHGUARD Control Tower
          </span>
          <span>
            Connected backend data{' '}
            <span className="footer-separator">/</span> Backend is the source of
            truth
          </span>
        </footer>
      </div>
    </div>
  );
}
