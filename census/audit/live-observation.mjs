import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const REPOSITORY_BINDING_EXCLUSIONS = Object.freeze([
  'v2/usf/census/audit.json',
  'v2/usf/census/closure.json',
]);
const isRepositoryBindingExcluded = (item) =>
  REPOSITORY_BINDING_EXCLUSIONS.includes(item) || item.startsWith('v2/usf/.work/');
const REQUIRED_ROLLBACK_FAULTS = Object.freeze([
  'clear-graph',
  'collect-observed',
  'commit',
  'contamination',
  'derive',
  'derived-insert',
  'integrity',
  'invalid-observed-rdf',
  'load',
  'rollback-response',
  'validate-authored',
  'validate-derived',
  'validate-observed',
  'verify-counts',
  'wrong-rule-output',
]);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

export const stableJson = (value) => JSON.stringify(stable(value));

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: null, maxBuffer: 128 * 1024 * 1024 });
}

export function repositoryState(repositoryRoot) {
  const root = fs.realpathSync(repositoryRoot);
  const paths = git(root, ['ls-files', '-co', '--exclude-standard', '-z'])
    .toString('utf8').split('\0').filter(Boolean)
    .filter((item) => !isRepositoryBindingExcluded(item)).sort();
  const accumulator = createHash('sha256');
  for (const relative of paths) {
    const absolute = path.resolve(root, relative);
    const content = !fs.existsSync(absolute)
      ? Buffer.from('deleted')
      : fs.lstatSync(absolute).isSymbolicLink()
        ? Buffer.from(`symlink:${fs.readlinkSync(absolute)}`)
        : fs.readFileSync(absolute);
    accumulator.update(relative).update('\0').update(sha256(content)).update('\n');
  }
  const statusEntries = git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
    .toString('utf8').split('\0').filter(Boolean);
  const includedStatus = [];
  for (let index = 0; index < statusEntries.length; index += 1) {
    const entry = statusEntries[index];
    const status = entry.slice(0, 2);
    const firstPath = entry.slice(3);
    const secondPath = status.includes('R') || status.includes('C') ? statusEntries[++index] : null;
    if (isRepositoryBindingExcluded(firstPath) || (secondPath && isRepositoryBindingExcluded(secondPath))) continue;
    includedStatus.push(entry);
    if (secondPath) includedStatus.push(secondPath);
  }
  const status = Buffer.from(includedStatus.join('\0'));
  return {
    gitHead: git(root, ['rev-parse', 'HEAD']).toString('utf8').trim(),
    files: paths.length,
    contentRootSha256: accumulator.digest('hex'),
    statusSha256: sha256(status),
    clean: status.length === 0,
    excludedPaths: [...REPOSITORY_BINDING_EXCLUSIONS, 'v2/usf/.work/'],
  };
}

function invalid(reasonCode) {
  return { status: 'invalid', reasonCode };
}

export function verifyStardogObservation(target, expectedFingerprint, repositoryRoot) {
  if (!target) return { status: 'missing', reasonCode: 'independent-stardog-observation-not-injected' };
  if (!expectedFingerprint) return invalid('independent-stardog-trust-anchor-missing');
  let envelope;
  try {
    envelope = JSON.parse(fs.readFileSync(path.resolve(target), 'utf8'));
  } catch {
    return invalid('independent-stardog-observation-unreadable');
  }
  try {
    const payload = envelope.payload;
    const publicKey = createPublicKey(envelope.signature?.publicKey ?? '');
    const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
    const signatureVerified = envelope.signature?.algorithm === 'Ed25519' &&
      envelope.signature?.publicKeyFingerprint === fingerprint &&
      verify(null, Buffer.from(stableJson(payload)), publicKey, Buffer.from(envelope.signature?.value ?? '', 'base64'));
    if (!signatureVerified) return invalid('independent-stardog-signature-invalid');
    if (fingerprint !== expectedFingerprint) return invalid('independent-stardog-trust-anchor-mismatch');
    if (payload?.observationKind !== 'stardog-access-boundary' || payload?.accessMethod !== 'official-sdk' ||
        payload?.connectionAttempted !== true || typeof payload?.observedAt !== 'string' || !payload.observedAt.length) {
      return invalid('independent-stardog-observation-contract-invalid');
    }
    const verification = payload.verification;
    if (verification?.reachable !== true || verification?.validationConforms !== true ||
        verification?.integrityConforms !== true || verification?.contaminationCount !== 0 ||
        verification?.missingGraphs?.length !== 0 || verification?.unexpectedGraphs?.length !== 0 ||
        verification?.countScope !== 'registered-usf-graphs' ||
        !Number.isSafeInteger(verification?.graphCount) || verification.graphCount < 0 ||
        !Number.isSafeInteger(verification?.tripleCount) || verification.tripleCount < 0 ||
        !Number.isFinite(verification?.readinessCount) || verification.readinessCount <= 0) {
      return invalid('independent-stardog-validation-invalid');
    }
    if (payload.comparison?.missingGraphs?.length !== 0 || payload.comparison?.unexpectedGraphs?.length !== 0 ||
        payload.comparison?.mismatchedGraphs?.length !== 0) {
      return invalid('independent-stardog-drift-nonzero');
    }
    const source = payload.sourceGraphDigests;
    const database = payload.databaseGraphDigests;
    if (!Array.isArray(source) || !Array.isArray(database) || source.length !== verification.graphCount ||
        stableJson(source) !== stableJson(database) ||
        source.reduce((sum, item) => sum + item.triples, 0) !== verification.tripleCount ||
        source.some((item) => item.algorithm !== 'URDNA2015' || item.digestAlgorithm !== 'sha256' || !/^[a-f0-9]{64}$/.test(item.sha256))) {
      return invalid('independent-stardog-digest-invalid');
    }
    const rollback = payload.rollback;
    if (rollback?.ok !== true || rollback?.digestsUnchanged !== true || !Array.isArray(rollback?.faults) ||
        rollback?.faultCount !== REQUIRED_ROLLBACK_FAULTS.length ||
        stableJson((rollback?.faults ?? []).map((item) => item.name).sort()) !== stableJson(REQUIRED_ROLLBACK_FAULTS) ||
        rollback.faults.some((item) => item.rollbackCount !== 1 || !Number.isSafeInteger(item.activationCount) || item.activationCount <= 0 ||
          typeof item.injectionPoint !== 'string' || item.injectionPoint.length === 0 || typeof item.errorPhase !== 'string' || item.errorPhase.length === 0) ||
        rollback?.commitOutcomeCoverage?.mode !== 'pre-dispatch-only' ||
        rollback?.commitOutcomeCoverage?.ambiguousPostDispatchOutcomeProven !== false ||
        typeof rollback?.commitOutcomeCoverage?.limitation !== 'string' || rollback.commitOutcomeCoverage.limitation.length === 0) {
      return invalid('independent-stardog-rollback-invalid');
    }
    if (stableJson(repositoryState(repositoryRoot)) !== stableJson(payload.repository)) {
      return invalid('independent-stardog-repository-binding-stale');
    }
    return {
      status: 'observed',
      observation: {
        observationKind: payload.observationKind,
        accessMethod: payload.accessMethod,
        connectionAttempted: payload.connectionAttempted,
        observedAt: payload.observedAt,
        countScope: verification.countScope,
        graphCount: verification.graphCount,
        tripleCount: verification.tripleCount,
        readinessCount: verification.readinessCount,
        validationConforms: true,
        integrityConforms: true,
        contaminationCount: 0,
        rollbackFaultCount: rollback.faultCount,
        digestsUnchangedAfterRollback: rollback.digestsUnchanged,
        canonicalizationAlgorithm: payload.canonicalization?.algorithm,
        publicKeyFingerprint: fingerprint,
        signatureVerified: true,
        repositoryBindingVerified: true,
        driftConforms: true,
      },
    };
  } catch {
    return invalid('independent-stardog-observation-invalid');
  }
}
