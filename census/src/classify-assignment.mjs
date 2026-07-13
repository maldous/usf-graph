import path from 'node:path';
import { classifyAssignment } from './classify.mjs';

const [manifest, output] = process.argv.slice(2);
if (!manifest || !output) throw new Error('usage: classify-assignment <manifest> <output>');
const records = classifyAssignment(path.resolve(manifest), path.resolve(output));
const counts = {};
for (const record of records) counts[record.v2ConceptCoverage] = (counts[record.v2ConceptCoverage] ?? 0) + 1;
process.stdout.write(`${JSON.stringify({ recordCount: records.length, coverage: counts })}\n`);
