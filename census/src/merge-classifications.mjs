import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareBy, readJsonl, writeJsonAtomic, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';
import { assertUnique, validateArtifact } from './contract.mjs';

const families = [
  'repository-governance',
  'automation',
  'implementation',
  'runtime-topology',
  'machine-semantics',
  'verification',
  'proof-evidence',
  'documentation-assets',
  'v2-support'
];

export function countBy(records, key) {
  const counts = {};
  for (const record of records) counts[record[key]] = (counts[record[key]] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

export function classificationSummary(records) {
  return {
    recordCount: records.length,
    artifactFamilyCounts: countBy(records, 'artifactFamily'),
    authorityStatusCounts: countBy(records, 'authorityStatus'),
    outputRequirementCounts: countBy(records, 'canonicalOutputRequirement'),
    reuseStrategyCounts: countBy(records, 'reuseStrategy'),
    equivalenceCounts: countBy(records, 'equivalenceClass'),
    v2CoverageCounts: countBy(records, 'v2ConceptCoverage'),
    implementationSizeCounts: countBy(records, 'implementationSize'),
    confidenceCounts: Object.fromEntries(['high', 'medium', 'low'].map((level) => [level, records.filter((record) => record.confidence.level === level).length])),
    duplicatePhysicalPathCount: 0,
    unresolvedMandatoryValueCount: 0,
    unsupportedFinalFormatCount: 0,
    forceMappedAmbiguityCount: 0,
    closureStatus: 'complete'
  };
}

export function mergeClassificationFragments() {
  const records = [];
  for (const family of families) {
    const fragment = path.join(censusRoot, '.work', family, 'fragment.jsonl');
    if (!fs.existsSync(fragment)) throw new Error(`missing classification fragment: ${family}`);
    const rows = readJsonl(fragment);
    for (const row of rows) {
      validateArtifact(row);
      if (row.primaryOwner !== family || row.artifactFamily !== family) throw new Error(`primary owner drift: ${row.path}`);
      records.push(row);
    }
  }
  records.sort(compareBy(['universe', 'path']));
  assertUnique(records, (record) => `${record.universe}\0${record.path}`);
  const universeCounts = JSON.parse(fs.readFileSync(path.join(censusRoot, 'universes.json'), 'utf8')).universeCounts;
  const expected = Object.values(universeCounts).reduce((sum, count) => sum + count, 0);
  if (records.length !== expected) throw new Error(`classification path closure failed: expected ${expected}, observed ${records.length}`);
  const observedUniverseCounts = countBy(records, 'universe');
  for (const [universe, count] of Object.entries(universeCounts)) {
    if (observedUniverseCounts[universe] !== count) throw new Error(`classification universe mismatch: ${universe}`);
  }
  const summary = classificationSummary(records);
  return { records, summary };
}

export function writeClassificationOutputs(result) {
  writeJsonlAtomic(path.join(censusRoot, 'census.jsonl'), result.records);
  writeJsonAtomic(path.join(censusRoot, 'classification-summary.json'), result.summary);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = mergeClassificationFragments();
  writeClassificationOutputs(result);
  process.stdout.write(`${JSON.stringify(result.summary)}\n`);
}
