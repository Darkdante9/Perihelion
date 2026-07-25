#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const auditPath = process.argv[2] ?? 'npm-audit.json';
const allowlistPath = process.argv[3] ?? '.github/dependency-audit-allowlist.json';

if (!fs.existsSync(auditPath)) {
  console.error(`Audit report not found at ${auditPath}`);
  process.exit(1);
}

const audit = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
const allowlist = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
const allowlisted = new Set(
  (allowlist.npm?.advisories ?? []).map((entry) => {
    const normalized = typeof entry === 'string' ? entry : entry?.package ?? entry?.id ?? '';
    const packageName = `${normalized}`.trim().toLowerCase();
    const title = `${typeof entry === 'string' ? '' : entry?.title ?? entry?.id ?? ''}`.trim().toLowerCase();
    return `${packageName}:${title}`;
  })
);

const findings = [];
for (const [packageName, vulnerability] of Object.entries(audit.vulnerabilities ?? {})) {
  const severity = `${vulnerability.severity ?? ''}`.toLowerCase();
  if (!['high', 'critical'].includes(severity)) {
    continue;
  }

  const viaEntries = Array.isArray(vulnerability.via) ? vulnerability.via : [vulnerability.via];
  for (const via of viaEntries) {
    const title = typeof via === 'string' ? via : via?.title ?? via?.name ?? '';
    const source = typeof via === 'object' ? `${via?.source ?? ''}` : '';
    const key = `${packageName}:${title || source}`.trim().toLowerCase();
    if (allowlisted.has(key)) {
      continue;
    }

    findings.push({
      package: packageName,
      severity,
      title: title || source || 'unspecified advisory',
    });
  }
}

if (findings.length > 0) {
  console.error('Unallowlisted high/critical npm advisories found:');
  for (const finding of findings) {
    console.error(`- ${finding.package} [${finding.severity}]: ${finding.title}`);
  }
  process.exit(1);
}

console.log('No unallowlisted high/critical npm advisories found.');
