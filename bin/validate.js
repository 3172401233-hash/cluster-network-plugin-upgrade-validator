#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { validateUpgradePlan } from '../src/validator.js';

async function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: node bin/validate.js <plan.json>');
    process.exit(2);
  }
  const input = JSON.parse(await readFile(file, 'utf8'));
  const report = validateUpgradePlan(input);
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(`validator error: ${err.message}`);
  process.exit(2);
});
