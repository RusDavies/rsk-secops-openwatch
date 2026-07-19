#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import {
  checkAdvisorySchemaPinDrift,
  formatAdvisorySchemaPinDriftReport,
} from '../lib/advisory-schema-drift-check.mjs';

function parseArgs(argv) {
  const options = {
    manifestPath: 'config/advisory-schema-pin-manifest.json',
    repoRoot: '.',
    format: 'text',
    output: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--manifest') options.manifestPath = argv[++i];
    else if (arg === '--repo-root') options.repoRoot = argv[++i];
    else if (arg === '--json') options.format = 'json';
    else if (arg === '--output') options.output = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      console.log(`Usage: node scripts/check-advisory-schema-pins.mjs [--manifest path] [--repo-root path] [--json] [--output path]\n\nFetches pinned upstream advisory schema/profile documents, compares sha256 digests, validates local drift fixture and package-lock evidence, and reports drift without enabling live fetchers.`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
const result = await checkAdvisorySchemaPinDrift(options);
const rendered = options.format === 'json' ? `${JSON.stringify(result, null, 2)}\n` : `${formatAdvisorySchemaPinDriftReport(result)}\n`;

if (options.output) writeFileSync(options.output, rendered);
else process.stdout.write(rendered);

if (!result.ok) process.exitCode = 1;
