'use client';

import React from 'react';

export default function SeverityBadge({ severity = 'LOW' }) {
  const sev = (severity || 'LOW').toUpperCase();

  const getTone = () => {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return 'tone-danger';
      case 'MEDIUM':
        return 'tone-warning';
      case 'LOW':
      case 'INFORMATIONAL':
      default:
        return 'tone-info';
    }
  };

  return (
    <span className={`status-badge ${getTone()} badge-small uppercase font-mono`}>
      {sev}
    </span>
  );
}
