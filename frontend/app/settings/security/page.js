'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  KeyRound,
  User,
  Mail,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  CheckCircle2,
  Database,
  Check,
  X,
  Copy,
  Clock,
  ShieldCheck,
  LogIn,
  Shield
} from 'lucide-react';
import { useAuth } from '@/components/AuthProvider';
import { changePassword } from '@/lib/api';

export default function SecuritySettingsPage() {
  const { user, loading: authLoading } = useAuth();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [copied, setCopied] = useState(false);

  // Password rules for new password
  const hasMinLength = newPassword.length >= 8;
  const hasUppercase = /[A-Z]/.test(newPassword);
  const hasLowercase = /[a-z]/.test(newPassword);
  const hasDigitOrSpecial = /[\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword);
  const passwordsMatch = newPassword && confirmPassword && newPassword === confirmPassword;
  const isValid = hasMinLength && hasUppercase && hasLowercase && hasDigitOrSpecial && passwordsMatch;

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!currentPassword) {
      setError('Please provide your current password.');
      return;
    }
    if (!isValid) {
      setError('New password must satisfy all security requirements.');
      return;
    }

    setSubmitting(true);
    try {
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setSuccess('Password updated successfully. Session token refreshed.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err.message || 'Failed to update password. Verify current password.');
    } finally {
      setSubmitting(false);
    }
  };

  const copyUserId = () => {
    if (user?.id) {
      navigator.clipboard.writeText(user.id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (authLoading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center space-y-4">
        <div className="inline-flex p-4 rounded-md bg-card border border-border text-primary">
          <Lock className="w-8 h-8" />
        </div>
        <h2 className="text-lg font-bold text-foreground">Authentication Required</h2>
        <p className="text-xs text-muted-foreground max-w-md mx-auto">
          You must be logged in to inspect tenant security settings and rotate credentials.
        </p>
        <Link
          href="/login?redirect=/settings/security"
          className="inline-flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground font-medium text-xs shadow-sm hover:opacity-90"
        >
          <LogIn className="w-3.5 h-3.5" />
          <span>Sign In to Continue</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            ACCESS &amp; TENANT CREDENTIALS
          </span>
          <h1>
            Security &amp; Account<span className="heading-dot">.</span>
          </h1>
          <p>
            Manage analyst profiles, rotate passwords, and inspect MongoDB tenant isolation parameters.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Profile Card & Tenant Specs */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-card border border-border rounded-md p-5 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-md bg-background border border-border text-primary flex items-center justify-center text-base font-bold font-mono uppercase">
                {user.name ? user.name.slice(0, 2).toUpperCase() : 'U'}
              </div>
              <div>
                <h3 className="font-semibold text-foreground text-sm">{user.name}</h3>
                <p className="text-xs text-muted-foreground break-all">{user.email}</p>
              </div>
            </div>

            <div className="pt-3 border-t border-border space-y-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Analyst ID:</span>
                <button
                  onClick={copyUserId}
                  className="font-mono text-[11px] text-foreground flex items-center gap-1 bg-background px-2 py-0.5 rounded border border-border cursor-pointer hover:bg-accent"
                  title="Click to copy ID"
                >
                  <span>{user.id ? `${user.id.slice(0, 12)}...` : 'N/A'}</span>
                  {copied ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3 text-muted-foreground" />}
                </button>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Role:</span>
                <span className="status-badge tone-info badge-small uppercase font-mono">
                  {user.role}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Status:</span>
                <span className="flex items-center gap-1 font-mono text-[11px] text-success">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  <span className="uppercase">{user.status}</span>
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Tenant Isolation:</span>
                <span className="status-badge tone-success badge-small font-mono">STRICT-ACTIVE</span>
              </div>

              {user.last_login && (
                <div className="pt-2 border-t border-border text-[11px] text-muted-foreground flex items-center gap-1.5">
                  <Clock className="w-3 h-3 text-muted-foreground" />
                  <span>Last login: {new Date(user.last_login).toLocaleString()}</span>
                </div>
              )}
            </div>
          </div>

          <div className="review-notice p-4 rounded border border-border bg-card space-y-2">
            <div className="flex items-center gap-2 text-foreground text-xs font-semibold uppercase font-mono">
              <Database className="w-3.5 h-3.5 text-primary" />
              <span>MongoDB Atlas Multi-Tenant Protection</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed text-[11px]">
              Every investigation and report generated by your analyst session is tagged with your user ID in database <code className="text-foreground">phishguard_ai</code>. Unauthorized users cannot view or download your forensics.
            </p>
          </div>
        </div>

        {/* Right Column: Password Rotation Form */}
        <div className="lg:col-span-7">
          <div className="bg-card border border-border rounded-md p-6 space-y-4">
            <div className="flex items-center gap-2 border-b border-border pb-3">
              <KeyRound className="w-4 h-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Rotate Account Password</h2>
            </div>

            {error && (
              <div className="p-3 rounded border border-danger/30 bg-danger/10 text-danger text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {success && (
              <div className="p-3 rounded border border-success/30 bg-success/10 text-success text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{success}</span>
              </div>
            )}

            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1.5">
                  Current Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Enter current password"
                    required
                    className="w-full pl-9 pr-10 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground cursor-pointer"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1.5">
                  New Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="At least 8 chars, uppercase, lowercase, digit"
                    required
                    className="w-full pl-9 pr-10 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1.5">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat new password"
                    required
                    className="w-full pl-9 pr-3 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              {/* Password criteria checklist */}
              <div className="p-3 rounded bg-background border border-border space-y-1.5 text-[11px]">
                <span className="text-muted-foreground font-mono text-[10px] uppercase font-semibold block">
                  Security Criteria for New Password
                </span>
                <div className="grid grid-cols-2 gap-1 text-[11px]">
                  <div className={`flex items-center gap-1.5 ${hasMinLength ? 'text-success' : 'text-muted-foreground'}`}>
                    {hasMinLength ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                    <span>8+ characters</span>
                  </div>
                  <div className={`flex items-center gap-1.5 ${hasUppercase ? 'text-success' : 'text-muted-foreground'}`}>
                    {hasUppercase ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                    <span>Uppercase letter</span>
                  </div>
                  <div className={`flex items-center gap-1.5 ${hasLowercase ? 'text-success' : 'text-muted-foreground'}`}>
                    {hasLowercase ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                    <span>Lowercase letter</span>
                  </div>
                  <div className={`flex items-center gap-1.5 ${hasDigitOrSpecial ? 'text-success' : 'text-muted-foreground'}`}>
                    {hasDigitOrSpecial ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                    <span>Number or symbol</span>
                  </div>
                </div>
                {confirmPassword && (
                  <div className={`pt-1 flex items-center gap-1.5 ${passwordsMatch ? 'text-success' : 'text-danger'}`}>
                    {passwordsMatch ? <Check className="w-3 h-3 text-success" /> : <X className="w-3 h-3 text-danger" />}
                    <span>{passwordsMatch ? 'Passwords match' : 'Passwords do not match'}</span>
                  </div>
                )}
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={submitting || !isValid || !currentPassword}
                  className="py-2 px-5 rounded bg-primary text-primary-foreground font-medium text-xs tracking-wide hover:opacity-90 transition disabled:opacity-40 cursor-pointer flex items-center gap-2"
                >
                  {submitting ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                      <span>Updating Hash...</span>
                    </>
                  ) : (
                    <>
                      <KeyRound className="w-3.5 h-3.5" />
                      <span>Update Password</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
