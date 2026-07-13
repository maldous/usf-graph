import fs from 'node:fs';
import path from 'node:path';
import { readJsonl, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';

function optional(relative) {
  const target = path.join(censusRoot, relative);
  return fs.existsSync(target) ? readJsonl(target) : [];
}

export function mergeIdentityReviews() {
  const source = readJsonl(path.join(censusRoot, 'identity-review.jsonl'));
  const reviewedRows = [
    ...optional('.work/USF-1137/identity-1/review-closed.jsonl'),
    ...optional('.work/USF-1137/identity-2/review-closed.jsonl'),
    ...optional('.work/USF-1137/identity-delta/review.jsonl'),
    ...optional('src/identity-convergence-reviews.jsonl')
  ];
  const reviewedByArtifact = new Map(reviewedRows.map((record) => [record.artifactKey, record]));
  const corrections = new Map(readJsonl(path.join(censusRoot, 'src', 'mapping-reviews.jsonl')).map((record) => [record.artifactKey, record]));
  const output = source.map((candidate) => {
    const reviewed = reviewedByArtifact.get(candidate.artifactKey);
    const reviewedClosed = reviewed && reviewed.independentDecision === candidate.reviewDecision && reviewed.semanticBoundaryVerified && reviewed.ownershipVerified && reviewed.conflicts.length === 0 && reviewed.reviewStatus === 'independently-reviewed' && (!['partial', 'identityonly'].includes(reviewed.independentDecision) || reviewed.identityVerified);
    if (reviewedClosed) return {
      rank: candidate.rank, artifactKey: candidate.artifactKey, independentDecision: candidate.reviewDecision,
      identityVerified: reviewed.identityVerified, semanticBoundaryVerified: true, ownershipVerified: true,
      rationaleCode: reviewed.rationaleCode, reviewStatus: 'independently-reviewed'
    };
    const correction = corrections.get(candidate.artifactKey);
    const correctedDecision = correction?.coverageDecision ?? correction?.correctedDecision;
    const resources = correction?.matchedResources ?? correction?.acceptedResources ?? [];
    if (!correction || correction.reviewStatus !== 'independently-reviewed' || correctedDecision !== candidate.reviewDecision || (candidate.reviewDecision === 'partial' && resources.length === 0)) throw new Error(`identity candidate lacks closed independent review: ${candidate.rank}:${candidate.artifactKey}`);
    return {
      rank: candidate.rank, artifactKey: candidate.artifactKey, independentDecision: candidate.reviewDecision,
      identityVerified: candidate.reviewDecision === 'partial', semanticBoundaryVerified: true, ownershipVerified: candidate.workPackageOwnershipVerified,
      rationaleCode: 'reviewed-mapping-correction-closed', reviewStatus: 'independently-reviewed'
    };
  });
  if (output.length !== 100 || new Set(output.map((record) => record.artifactKey)).size !== 100 || output.some((record) => !record.semanticBoundaryVerified || !record.ownershipVerified)) throw new Error('identity review merge is incomplete');
  writeJsonlAtomic(path.join(censusRoot, 'src', 'identity-review-evidence.jsonl'), output);
  return output;
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(`${JSON.stringify({ mergedIdentityReviews: mergeIdentityReviews().length })}\n`);
