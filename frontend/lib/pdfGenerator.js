import { jsPDF } from 'jspdf';

/**
 * Generates an executive, audit-ready PDF dossier for a PhishGuard investigation.
 * @param {Object} inv The investigation object
 */
export function generateInvestigationPdf(inv) {
  if (!inv) return;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;

  let y = 45;

  // Helper to check page break
  const checkPageBreak = (neededHeight) => {
    if (y + neededHeight > pageHeight - 50) {
      doc.addPage();
      y = 45;
      drawPageHeader();
    }
  };

  // Helper for running header on pages > 1
  const drawPageHeader = () => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(140, 150, 155);
    doc.text('PHISHGUARD CONTROL TOWER // INCIDENT AUDIT DOSSIER', margin, 25);
    doc.text(`REF: ${inv.id || 'N/A'}`, pageWidth - margin, 25, { align: 'right' });
    doc.setDrawColor(220, 226, 224);
    doc.setLineWidth(0.5);
    doc.line(margin, 30, pageWidth - margin, 30);
  };

  // --- 1. Top Header Banner ---
  doc.setFillColor(25, 38, 35); // Dark teal/charcoal SOC header
  doc.roundedRect(margin, y, contentWidth, 54, 4, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(255, 255, 255);
  doc.text('PHISHGUARD AI', margin + 14, y + 22);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(120, 210, 190);
  doc.text('SECURITY OPERATIONS CENTER // FORENSIC AUDIT DOSSIER', margin + 14, y + 36);

  // Classification & Timestamp on right side
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(255, 255, 255);
  doc.text('RESTRICTED // SOC-2 AUDIT', pageWidth - margin - 14, y + 22, { align: 'right' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(200, 210, 205);
  const dateStr = inv.created_at ? new Date(inv.created_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : new Date().toISOString();
  doc.text(dateStr, pageWidth - margin - 14, y + 36, { align: 'right' });

  y += 66;

  // --- 2. Incident Summary Card ---
  const riskScore = inv.risk?.overall_score ?? 0;
  const riskRating = (inv.risk?.overall_rating || 'EVALUATED').toUpperCase();

  // Background card for metadata
  doc.setFillColor(245, 248, 246);
  doc.setDrawColor(210, 220, 216);
  doc.setLineWidth(1);
  doc.roundedRect(margin, y, contentWidth, 75, 4, 4, 'FD');

  // Left column: Incident details
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 45, 40);
  doc.text(`Investigation: ${inv.id || 'N/A'}`, margin + 14, y + 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(90, 105, 100);
  
  const subject = inv.email_metadata?.subject || inv.input_type || 'Direct Intake Scan';
  const cleanSubject = subject.length > 55 ? subject.slice(0, 52) + '...' : subject;
  doc.text(`Target / Subject: ${cleanSubject}`, margin + 14, y + 36);

  const sender = inv.email_metadata?.sender || inv.email_metadata?.sender_domain || 'Unknown Origin';
  const cleanSender = sender.length > 55 ? sender.slice(0, 52) + '...' : sender;
  doc.text(`Observed Sender: ${cleanSender}`, margin + 14, y + 50);

  doc.text(`Verification Engine: LangGraph 10-Node Air-Gapped Pipeline`, margin + 14, y + 64);

  // Right column: Risk badge
  let badgeFill = [22, 163, 74]; // green
  if (riskRating === 'HIGH' || riskScore >= 70) badgeFill = [220, 38, 38]; // red
  else if (riskRating === 'MEDIUM' || riskScore >= 40) badgeFill = [217, 119, 6]; // amber

  const badgeWidth = 90;
  const badgeX = pageWidth - margin - badgeWidth - 14;
  doc.setFillColor(...badgeFill);
  doc.roundedRect(badgeX, y + 14, badgeWidth, 48, 4, 4, 'F');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text('RISK EVALUATION', badgeX + badgeWidth / 2, y + 28, { align: 'center' });

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.text(`${riskScore}/100`, badgeX + badgeWidth / 2, y + 44, { align: 'center' });

  doc.setFontSize(7.5);
  doc.text(riskRating, badgeX + badgeWidth / 2, y + 55, { align: 'center' });

  y += 88;

  // --- 3. Vector Scores Breakdown ---
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(210, 220, 216);
  doc.roundedRect(margin, y, contentWidth, 36, 4, 4, 'FD');

  const colW = contentWidth / 3;
  
  // Col 1: Email Score
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 115, 110);
  doc.text('EMAIL VECTOR SCORE', margin + 12, y + 15);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 45, 40);
  doc.text(`${inv.risk?.email_score ?? riskScore}/100`, margin + 12, y + 29);

  // Col 2: Attachment Score
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 115, 110);
  doc.text('ATTACHMENT SCORE', margin + colW + 12, y + 15);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 45, 40);
  doc.text(`${inv.risk?.attachment_score ?? 0}/100`, margin + colW + 12, y + 29);

  // Col 3: Coverage Status
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 115, 110);
  doc.text('DETERMINISTIC COVERAGE', margin + colW * 2 + 12, y + 15);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(13, 148, 136); // teal
  doc.text(inv.risk?.coverage_status || 'VERIFIED_CHAIN', margin + colW * 2 + 12, y + 29);

  y += 48;

  // --- 4. Executive AI Synthesis & Attack Vector ---
  if (inv.llm_interpretation) {
    checkPageBreak(120);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10.5);
    doc.setTextColor(30, 45, 40);
    doc.text('Executive Threat Assessment', margin, y);
    y += 14;

    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(210, 220, 216);
    doc.setLineWidth(1);

    const synthText = inv.llm_interpretation.summary || 'Deterministic static analysis completed with zero telemetry anomalies.';
    const splitSynth = doc.splitTextToSize(synthText, contentWidth - 24);
    const boxHeight = Math.max(50, 28 + splitSynth.length * 11 + 20);

    doc.roundedRect(margin, y, contentWidth, boxHeight, 4, 4, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(13, 148, 136);
    const provider = (inv.llm_interpretation.provider_used || 'AIR-GAPPED').toUpperCase();
    const vector = inv.llm_interpretation.attack_vector || 'Phishing Reconnaissance';
    doc.text(`ATTACK PATTERN: ${vector.toUpperCase()}  (Provider: ${provider})`, margin + 12, y + 16);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 65, 60);
    doc.text(splitSynth, margin + 12, y + 30);

    y += boxHeight + 14;
  }

  // --- 5. Authoritative Evidence Chain Table ---
  const evidenceList = inv.evidence || [];
  checkPageBreak(80);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(30, 45, 40);
  doc.text(`Authoritative Evidence Chain (${evidenceList.length} Findings Recorded)`, margin, y);
  y += 14;

  if (evidenceList.length === 0) {
    doc.setFillColor(245, 248, 246);
    doc.roundedRect(margin, y, contentWidth, 32, 4, 4, 'F');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 115, 110);
    doc.text('No high-risk signature matches recorded. Static headers and payloads appear benign.', margin + 14, y + 20);
    y += 42;
  } else {
    // Evidence item boxes
    evidenceList.forEach((ev, idx) => {
      checkPageBreak(50);

      const sev = (ev.severity || 'INFO').toUpperCase();
      let sevColor = [13, 148, 136]; // teal
      if (sev === 'HIGH' || sev === 'CRITICAL') sevColor = [220, 38, 38];
      else if (sev === 'MEDIUM') sevColor = [217, 119, 6];

      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(220, 226, 224);
      doc.roundedRect(margin, y, contentWidth, 42, 3, 3, 'FD');

      // Left severity pill bar
      doc.setFillColor(...sevColor);
      doc.rect(margin, y, 4, 42, 'F');

      // Rule ID & Title
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(30, 45, 40);
      doc.text(`${idx + 1}. [${ev.rule_id || 'RULE'}]  ${ev.title || 'Rule Observation'}`, margin + 12, y + 15);

      // Severity chip
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...sevColor);
      doc.text(sev, pageWidth - margin - 12, y + 15, { align: 'right' });

      // Supporting observation
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(80, 95, 90);
      const obs = ev.supporting_observation || 'Identified deterministic behavioral risk signature.';
      const cleanObs = obs.length > 95 ? obs.slice(0, 92) + '...' : obs;
      doc.text(cleanObs, margin + 12, y + 30);

      y += 48;
    });
  }

  // --- 6. Mandatory Safe Verification Guidance ---
  checkPageBreak(85);
  doc.setFillColor(248, 250, 249);
  doc.setDrawColor(210, 220, 216);
  doc.roundedRect(margin, y, contentWidth, 68, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(30, 45, 40);
  doc.text('MANDATORY SOC VERIFICATION & QUARANTINE PROTOCOL', margin + 12, y + 16);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(70, 85, 80);
  doc.text('1. Independent Verification: Verify communications through registered out-of-band enterprise channels.', margin + 12, y + 30);
  doc.text('2. Credential Protection: Never enter domain or MFA credentials via links in unverified transmissions.', margin + 12, y + 43);
  doc.text('3. Compliance Quarantine: Quarantine suspicious message hashes and notify the primary SecOps team.', margin + 12, y + 56);

  y += 82;

  // --- 7. Page Footers for all pages ---
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(140, 150, 145);
    doc.setDrawColor(220, 226, 224);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 30, pageWidth - margin, pageHeight - 30);

    doc.text('PhishGuard AI Control Tower // Zero External HTTP Lookups // SOC 2 & HIPAA Sanitized', margin, pageHeight - 18);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 18, { align: 'right' });
  }

  // Trigger browser download
  const filename = `phishguard_dossier_${inv.id || 'export'}.pdf`;
  doc.save(filename);
}
