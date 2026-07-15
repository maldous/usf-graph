#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream, copyFileSync, existsSync, mkdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { COPYFILE_EXCL } from 'node:constants';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const casRoot = process.env.USF_CAS_ROOT ? resolve(process.env.USF_CAS_ROOT) : null;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

async function fileDigest(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

function requireLocalRoot() {
  if (!casRoot) throw new Error('USF_CAS_ROOT must name an operator-owned local directory outside Git');
  const rel = relative(repositoryRoot, casRoot);
  if (!rel || (!rel.startsWith('..') && !resolve(rel).startsWith('..'))) throw new Error('USF_CAS_ROOT must be outside the repository');
  mkdirSync(casRoot, { recursive: true, mode: 0o700 });
  return casRoot;
}

function payloadPath(root, digest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error('digest is not canonical SHA-256');
  const hex = digest.slice(7);
  return resolve(root, 'sha256', hex.slice(0, 2), hex);
}

async function put(path, artefactFamily, representationFormat, mediaType, artifactType) {
  const root = requireLocalRoot();
  const source = resolve(path);
  const stat = statSync(source);
  if (!stat.isFile()) throw new Error('payload must be a regular file');
  const digest = await fileDigest(source);
  const target = payloadPath(root, digest);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  if (!existsSync(target)) {
    const temporary = `${target}.incoming-${process.pid}`;
    try {
      copyFileSync(source, temporary, COPYFILE_EXCL);
      if (await fileDigest(temporary) !== digest) throw new Error('payload changed while being collected');
      renameSync(temporary, target);
    } finally {
      rmSync(temporary, { force: true });
    }
  }
  const observed = statSync(target);
  if (!observed.isFile() || observed.size !== stat.size || await fileDigest(target) !== digest) throw new Error('existing CAS object does not match its digest');
  return {
    id: `urn:usf:externalpayloaddescriptor:${digest.slice(7)}`,
    digest,
    artefactFamily,
    representationFormat,
    mediaType,
    byteSize: observed.size,
    locator: `cas://sha256/${digest.slice(7)}`,
    artifactType,
    storageClass: 'urn:usf:storageclass:contentaddressedobjectstorage',
  };
}

async function verify(digest) {
  const root = requireLocalRoot();
  const path = payloadPath(root, digest);
  if (!existsSync(path)) return { verified: false, digest, code: 'ARTIFACT_NOT_FOUND' };
  const stat = statSync(path);
  const observedDigest = stat.isFile() ? await fileDigest(path) : null;
  return { verified: observedDigest === digest, digest, observedDigest, byteSize: stat.size };
}

try {
  const [command, ...args] = process.argv.slice(2);
  let result;
  if (command === 'put' && args.length === 5) result = await put(...args);
  else if (command === 'verify' && args.length === 1) result = await verify(args[0]);
  else throw new Error('usage: local-cas.mjs put FILE ARTEFACT_FAMILY REPRESENTATION_FORMAT MEDIA_TYPE ARTIFACT_TYPE | verify SHA256_DIGEST');
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  fail(error.message);
}
