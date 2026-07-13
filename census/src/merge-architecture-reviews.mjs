import fs from 'node:fs';
import path from 'node:path';
import { sha256, writeJsonAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';

function read(relative) {
  const text = fs.readFileSync(path.join(censusRoot, relative), 'utf8');
  return { digest: sha256(text), value: JSON.parse(text) };
}

export function mergeArchitectureReviews() {
  const convergence = read('.work/USF-1142/convergence/review.json');
  const missing = read('.work/USF-1142/missing-entirely-review.json');
  if (convergence.value.verdict !== 'pass' || convergence.value.reviewStatus !== 'independently-reviewed' || Object.values(convergence.value.findingCounts).some((count) => count !== 0)) throw new Error('convergence review is not closed');
  if (missing.value.verdict !== 'pass' || missing.value.reviewStatus !== 'independently-reviewed' || missing.value.unownedCount !== 0 || missing.value.unplannedCount !== 0 || missing.value.conflicts.length !== 0) throw new Error('missing-entirely review is not closed');
  const result = {
    reviewId: 'hardened-census-architectural-acceptance',
    reviewStatus: 'independently-reviewed',
    verdict: 'pass',
    inputDigests: { convergence: convergence.digest, missingEntirely: missing.digest },
    convergence: convergence.value,
    missingEntirely: missing.value
  };
  writeJsonAtomic(path.join(censusRoot, 'architectural-review.json'), result);
  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(`${JSON.stringify({ verdict: mergeArchitectureReviews().verdict })}\n`);
