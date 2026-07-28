#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  createHash, createPrivateKey, createPublicKey, sign, verify,
} from 'node:crypto';
import {
  chmodSync, closeSync, constants as fsConstants, existsSync, fstatSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, readlinkSync, realpathSync,
  statSync, writeFileSync,
} from 'node:fs';
import {
  createRequire, isBuiltin, registerHooks,
} from 'node:module';
import {
  dirname, isAbsolute, join, relative, resolve, sep,
} from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
  inspectProviderProofNodeDependencies,
  normaliseDeterministicPytestOutput,
  prepareExactSessionOutputRoot,
  PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
  runProviderMaterialisationAuthorityMutations,
  verifyProviderProofNodeDependencyEvidence,
} from './provider-materialisation-authority-mutations.mjs';
import {
  inspectPinnedPythonRuntime,
  spawnPinnedLocalShaclRuntime,
} from '../semantic-model-compilation/local-shacl-validation.mjs';
import {
  collectNodeRuntimeClosure,
  readTrackedTreeSnapshot,
  runtimeDescriptorFromEvidence,
} from './authority-execution-hermeticity.mjs';
import {
  PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
  verifyProviderProofSourceManifest,
} from './provider-proof-source-manifest.mjs';

const semanticRoot = resolve(dirname(import.meta.filename), '..', '..');
const PROVIDER_PROOF_PATH =
  'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs';
export const PROVIDER_PROOF_EVIDENCE_SCHEMA_VERSION = 3;
export const PROVIDER_PROOF_RECEIPT_SCHEMA_VERSION = 3;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const cases = [];
const commands = [];
let providerCredentialEnvironmentForwarded = false;
let outputRoot;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const HERMETIC_COMMAND_ENV = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  PATH: '/usr/bin:/bin',
  TZ: 'UTC',
  XDG_CONFIG_HOME: '/nonexistent',
});
const GIT_EXECUTABLE_PATH = '/usr/bin/git';
const GIT_NATIVE_OBJECTS = Object.freeze([
  ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', 'sha256:02bcda52c1a5dfc236f94d9e5255b4a0e26347d8a372a5223b650e31f291ce3c'],
  ['/usr/lib/x86_64-linux-gnu/libc.so.6', 'sha256:6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421'],
  ['/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2', 'sha256:19c626251526131ac9340826c8f7bcb693c6ceb9d5da55919c3aa45d972b704f'],
  ['/usr/lib/x86_64-linux-gnu/libz.so.1.2.13', 'sha256:7e2a72b4c4b38c61e6962de6e3f4a5e9ae692e732c68deead10a7ce2135a7f68'],
]);
const gitNativeObjectRecords = GIT_NATIVE_OBJECTS.map(([path, expectedDigest]) => {
  const resolvedPath = realpathSync(path);
  const digest = sha256(readFileSync(resolvedPath));
  if (digest !== expectedDigest) throw new Error('GIT_NATIVE_OBJECT_DIGEST_MISMATCH');
  return { path: resolvedPath, digest, byteSize: lstatSync(resolvedPath).size };
});
const gitRuntime = Object.freeze({
  executablePath: GIT_EXECUTABLE_PATH,
  resolvedExecutablePath: realpathSync(GIT_EXECUTABLE_PATH),
  executableDigest: sha256(readFileSync(realpathSync(GIT_EXECUTABLE_PATH))),
});
if (gitRuntime.executableDigest !== 'sha256:2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d') {
  throw new Error('GIT_EXECUTABLE_DIGEST_MISMATCH');
}
const gitRuntimeDependencyEvidence = Object.freeze({
  schemaVersion: 1,
  executableDigest: gitRuntime.executableDigest,
  nativeObjectCount: gitNativeObjectRecords.length,
  nativeObjectSetDigest: sha256(canonicalJson(gitNativeObjectRecords)),
});

function runtimeObjectRecord(path) {
  const canonicalPath = realpathSync(path);
  const stat = lstatSync(canonicalPath, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('ADMITTED_RUNTIME_OBJECT_NOT_EXACT_FILE');
  }
  return Object.freeze({
    path: canonicalPath,
    digest: sha256(readFileSync(canonicalPath)),
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    mode: Number(stat.mode & 0o7777n),
    linkCount: stat.nlink.toString(),
    byteLength: stat.size.toString(),
    ctimeNanoseconds: stat.ctimeNs.toString(),
  });
}

function admittedGitRuntimeDescriptor() {
  const mappedNativeObjects = [
    GIT_EXECUTABLE_PATH,
    ...GIT_NATIVE_OBJECTS.map(([path]) => path),
  ].map(runtimeObjectRecord).sort((left, right) => utf8Compare(left.path, right.path));
  const executable = mappedNativeObjects.find(
    ({ path }) => path === gitRuntime.resolvedExecutablePath,
  );
  if (!executable || executable.digest !== gitRuntime.executableDigest) {
    throw new Error('ADMITTED_GIT_EXECUTABLE_MISMATCH');
  }
  return Object.freeze({
    schemaVersion: 1,
    executable,
    mappedNativeObjectCount: mappedNativeObjects.length,
    mappedNativeObjectSetDigest: sha256(canonicalJson(mappedNativeObjects)),
    mappedNativeObjects: Object.freeze(mappedNativeObjects),
  });
}
export const FOCUSED_PYTEST_BOOTSTRAP = String.raw`
import sys

snapshot_stdlib = sys.argv.pop(1)
sys.path.insert(0, snapshot_stdlib)

import hashlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import json
import os
import pathlib

site_packages = pathlib.Path(sys.argv.pop(1)).resolve()
factory_root = pathlib.Path(sys.argv.pop(1)).resolve()
pycache_root = pathlib.Path(sys.argv.pop(1)).resolve()
source_manifest_path = pathlib.Path(sys.argv.pop(1)).resolve()
poison_site = pathlib.Path(sys.argv.pop(1)).resolve()
poison_marker = pathlib.Path(sys.argv.pop(1)).resolve()
isolation_evidence_path = pathlib.Path(sys.argv.pop(1)).resolve()
factory_source = (factory_root / "src").resolve()
sys.path[:0] = [factory_source.as_posix(), poison_site.as_posix(), site_packages.as_posix()]
sys.pycache_prefix = pycache_root.as_posix()
sys.dont_write_bytecode = True


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
if manifest.get("schemaVersion") != 1:
    raise RuntimeError("PYTHON_SOURCE_SNAPSHOT_SCHEMA_INVALID")
source_map = {}
for entry in manifest.get("sources", []):
    source = pathlib.Path(entry["sourcePath"]).resolve()
    snapshot = pathlib.Path(entry["snapshotPath"]).resolve()
    if not snapshot.is_file() or snapshot.is_symlink():
        raise RuntimeError("PYTHON_SOURCE_SNAPSHOT_FILE_INVALID:" + snapshot.as_posix())
    if sha256(snapshot.read_bytes()) != entry["digest"]:
        raise RuntimeError("PYTHON_SOURCE_SNAPSHOT_DIGEST_MISMATCH:" + snapshot.as_posix())
    source_map[source.as_posix()] = snapshot
safe_manifest = {
    "pyvenvConfigurationDigest": manifest["pyvenvConfigurationDigest"],
    "sourceCount": len(manifest.get("sources", [])),
    "sourceSetDigest": manifest["sourceSetDigest"],
}
if sha256(canonical_json(safe_manifest).encode("utf-8")) != manifest["evidenceDigest"]:
    raise RuntimeError("PYTHON_SOURCE_SNAPSHOT_EVIDENCE_DIGEST_MISMATCH")


class SnapshotSourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, fullname, original_path, snapshot_path):
        super().__init__(fullname, original_path)
        self._snapshot_path = snapshot_path

    def get_code(self, fullname):
        source_bytes = self._snapshot_path.read_bytes()
        return self.source_to_code(source_bytes, self.path)


class SnapshotSourceFinder(importlib.abc.MetaPathFinder):
    @staticmethod
    def find_spec(fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or not isinstance(spec.loader, importlib.machinery.SourceFileLoader):
            return spec
        original_path = pathlib.Path(spec.origin).resolve().as_posix()
        snapshot_path = source_map.get(original_path)
        if snapshot_path is None:
            if original_path.startswith(site_packages.as_posix() + "/"):
                raise RuntimeError("UNSNAPSHOTTED_SITE_PACKAGE_SOURCE:" + original_path)
            return spec
        spec.loader = SnapshotSourceLoader(fullname, original_path, snapshot_path)
        return spec


sys.meta_path.insert(0, SnapshotSourceFinder())

import pytest
import usf_factory

actual_origin = pathlib.Path(usf_factory.__file__).resolve()
if actual_origin != factory_source / "usf_factory" / "__init__.py":
    raise RuntimeError("FACTORY_IMPORT_ORIGIN_MISMATCH:" + actual_origin.as_posix())
if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
    raise RuntimeError("PYTHON_SITE_CUSTOMIZATION_LOADED")
if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
    raise RuntimeError("PYTEST_PLUGIN_AUTOLOAD_NOT_DISABLED")
poison_entries = [
    item for item in importlib.metadata.entry_points(group="pytest11")
    if item.name == "usf-poison-autoload"
]
if len(poison_entries) != 1:
    raise RuntimeError("PYTEST_POISON_PLUGIN_NOT_DISCOVERABLE")
if poison_marker.exists():
    raise RuntimeError("PYTEST_POISON_PLUGIN_PRELOADED")

status = pytest.main(["-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin", *sys.argv[1:]])
if poison_marker.exists():
    raise RuntimeError("PYTEST_PLUGIN_AUTOLOAD_OCCURRED")
for entry in manifest.get("sources", []):
    snapshot = pathlib.Path(entry["snapshotPath"]).resolve()
    if not snapshot.is_file() or snapshot.is_symlink() or sha256(snapshot.read_bytes()) != entry["digest"]:
        raise RuntimeError("PYTHON_SOURCE_SNAPSHOT_MOVED:" + snapshot.as_posix())
isolation_evidence = {
    "pluginAutoloadDisabled": True,
    "poisonPluginDiscoverable": True,
    "poisonPluginLoaded": False,
    "pyvenvConfigurationDigest": manifest["pyvenvConfigurationDigest"],
    "runtimeSourceIsolationMode": "READ_ONLY_EXACT_SOURCE_SNAPSHOT_LOADER_WITH_FD_PINNED_NATIVE_RUNTIME",
    "runtimeSourceFileCount": len(manifest.get("sources", [])),
    "runtimeSourceSetDigest": manifest["sourceSetDigest"],
}
isolation_evidence_path.write_text(canonical_json(isolation_evidence), encoding="utf-8")
paths = set()
for line in pathlib.Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
    fields = line.split()
    mapped_path = " ".join(fields[5:]) if len(fields) >= 6 else ""
    if mapped_path.startswith("/") and mapped_path.endswith(" (deleted)"):
        raise RuntimeError("MAPPED_RUNTIME_OBJECT_DELETED:" + mapped_path)
    if mapped_path.startswith("/"):
        path = pathlib.Path(mapped_path).resolve(strict=True)
        if not path.is_file():
            raise RuntimeError("MAPPED_RUNTIME_OBJECT_NOT_FILE:" + mapped_path)
        paths.add(path)
records = [
    {
        "path": path.as_posix(),
        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        "byteSize": path.stat().st_size,
    }
    for path in sorted(paths, key=lambda item: item.as_posix().encode("utf-8"))
]
runtime = {
    "mappedSystemObjectCount": len(records),
    "mappedSystemObjectSetDigest": "sha256:" + hashlib.sha256(
        json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest(),
    "siteCustomizationLoaded": False,
}
print("USF_PYTEST_RUNTIME_EVIDENCE=" + json.dumps(runtime, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
raise SystemExit(status)
`;

function identityOf(stat) {
  return {
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    mode: stat.mode.toString(),
    linkCount: stat.nlink.toString(),
    size: stat.size.toString(),
    modifiedTimeNs: stat.mtimeNs.toString(),
    changedTimeNs: stat.ctimeNs.toString(),
  };
}

function exactFileBytes(path, label) {
  const beforePathStat = lstatSync(path, { bigint: true });
  if (!beforePathStat.isFile() || beforePathStat.isSymbolicLink()) {
    throw new Error(`${label}_NOT_EXACT_FILE`);
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const beforeDescriptorIdentity = identityOf(fstatSync(descriptor, { bigint: true }));
    if (canonicalJson(beforeDescriptorIdentity) !== canonicalJson(identityOf(beforePathStat))) {
      throw new Error(`${label}_OPEN_IDENTITY_MISMATCH`);
    }
    const bytes = readFileSync(descriptor);
    const afterDescriptorIdentity = identityOf(fstatSync(descriptor, { bigint: true }));
    const afterPathStat = lstatSync(path, { bigint: true });
    if (canonicalJson(afterDescriptorIdentity) !== canonicalJson(beforeDescriptorIdentity)
      || canonicalJson(identityOf(afterPathStat)) !== canonicalJson(beforeDescriptorIdentity)) {
      throw new Error(`${label}_MOVED_DURING_READ`);
    }
    return { bytes, identity: beforeDescriptorIdentity };
  } finally {
    closeSync(descriptor);
  }
}

function assertPathWithin(root, path, code) {
  const containment = relative(root, path);
  if (containment === '..' || containment.startsWith(`..${sep}`) || isAbsolute(containment)) {
    throw new Error(code);
  }
  return path;
}

function makeExactDirectory(path, directories) {
  mkdirSync(path, { recursive: false, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error('PRIVATE_SNAPSHOT_DIRECTORY_INVALID');
  }
  directories.push(path);
}

function materialiseTrackedSnapshot({
  snapshot,
  destination,
  createRoot = true,
  seal = true,
}) {
  if (!snapshot || snapshot.schemaVersion !== 1 || !Array.isArray(snapshot.records)) {
    throw new Error('TRACKED_SOURCE_SNAPSHOT_REQUIRED');
  }
  const directories = [];
  if (createRoot) {
    makeExactDirectory(destination, directories);
  } else {
    const stat = lstatSync(destination);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(destination) !== destination) {
      throw new Error('TRACKED_SOURCE_SNAPSHOT_DESTINATION_INVALID');
    }
  }
  for (const record of snapshot.records) {
    if (!Buffer.isBuffer(record.bytes)
      || sha256(record.bytes) !== record.digest
      || record.bytes.length !== record.byteLength
      || !/^(?:100644|100755)$/.test(record.mode)) {
      throw new Error(`TRACKED_SOURCE_SNAPSHOT_RECORD_INVALID:${record.path}`);
    }
    let directory = destination;
    for (const component of record.path.split('/').slice(0, -1)) {
      directory = join(directory, component);
      assertPathWithin(destination, directory, 'TRACKED_SOURCE_SNAPSHOT_PATH_ESCAPE');
      if (!existsSync(directory)) makeExactDirectory(directory, directories);
    }
    const path = join(destination, ...record.path.split('/'));
    assertPathWithin(destination, path, 'TRACKED_SOURCE_SNAPSHOT_PATH_ESCAPE');
    writeFileSync(path, record.bytes, {
      flag: 'wx',
      mode: record.mode === '100755' ? 0o500 : 0o400,
    });
    const copied = exactFileBytes(path, 'TRACKED_SOURCE_SNAPSHOT_FILE');
    if (copied.bytes.length !== record.byteLength || sha256(copied.bytes) !== record.digest) {
      throw new Error(`TRACKED_SOURCE_SNAPSHOT_COPY_MISMATCH:${record.path}`);
    }
  }
  if (seal) {
    for (const directory of directories.reverse()) chmodSync(directory, 0o500);
  }
  return Object.freeze({
    root: destination,
    commit: snapshot.commit,
    tree: snapshot.tree,
    recordCount: snapshot.records.length,
    sourceSetDigest: snapshot.evidence.sourceSetDigest,
    directories: Object.freeze([...directories]),
  });
}

function copyExactTree(sourceRoot, destinationRoot, directories) {
  makeExactDirectory(destinationRoot, directories);
  const visit = (sourceDirectory, destinationDirectory) => {
    const beforeDirectory = identityOf(lstatSync(sourceDirectory, { bigint: true }));
    for (const name of readdirSync(sourceDirectory).sort(utf8Compare)) {
      const source = join(sourceDirectory, name);
      const destination = join(destinationDirectory, name);
      const stat = lstatSync(source, { bigint: true });
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        makeExactDirectory(destination, directories);
        visit(source, destination);
      } else if (stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n) {
        const exact = exactFileBytes(source, 'NODE_DEPENDENCY_SOURCE');
        writeFileSync(destination, exact.bytes, {
          flag: 'wx',
          mode: Number(stat.mode & 0o111n) === 0 ? 0o400 : 0o500,
        });
        if (sha256(exactFileBytes(destination, 'NODE_DEPENDENCY_SNAPSHOT').bytes)
          !== sha256(exact.bytes)) {
          throw new Error('NODE_DEPENDENCY_SNAPSHOT_COPY_MISMATCH');
        }
      } else {
        throw new Error('NODE_DEPENDENCY_SNAPSHOT_ENTRY_INVALID');
      }
    }
    if (canonicalJson(identityOf(lstatSync(sourceDirectory, { bigint: true })))
      !== canonicalJson(beforeDirectory)) {
      throw new Error('NODE_DEPENDENCY_SOURCE_DIRECTORY_MOVED');
    }
  };
  visit(sourceRoot, destinationRoot);
}

function createPrivateNodeDependencySnapshot({
  repositoryRoot,
  destination,
  admittedEvidence,
  seal = true,
}) {
  verifyProviderProofNodeDependencyEvidence(admittedEvidence, { repositoryRoot });
  const directories = [];
  makeExactDirectory(destination, directories);
  for (const name of ['package.json', 'package-lock.json']) {
    const source = exactFileBytes(join(repositoryRoot, name), 'NODE_PACKAGE_CONTEXT');
    writeFileSync(join(destination, name), source.bytes, { flag: 'wx', mode: 0o400 });
  }
  const nodeModules = join(destination, 'node_modules');
  makeExactDirectory(nodeModules, directories);
  for (const { name } of admittedEvidence.packages) {
    const source = join(repositoryRoot, 'node_modules', ...name.split('/'));
    let destinationPackage = nodeModules;
    const components = name.split('/');
    if (components.length === 2) {
      destinationPackage = join(nodeModules, components[0]);
      if (!existsSync(destinationPackage)) makeExactDirectory(destinationPackage, directories);
      destinationPackage = join(destinationPackage, components[1]);
    } else {
      [destinationPackage] = [join(nodeModules, components[0])];
    }
    copyExactTree(source, destinationPackage, directories);
  }
  const copiedEvidence = inspectProviderProofNodeDependencies({ repositoryRoot: destination });
  if (canonicalJson(copiedEvidence) !== canonicalJson(admittedEvidence)) {
    throw new Error('NODE_DEPENDENCY_PRIVATE_SNAPSHOT_EVIDENCE_MISMATCH');
  }
  verifyProviderProofNodeDependencyEvidence(admittedEvidence, { repositoryRoot });
  if (seal) {
    for (const directory of directories.reverse()) chmodSync(directory, 0o500);
  }
  return Object.freeze({
    root: destination,
    evidence: copiedEvidence,
    sourceSetDigest: copiedEvidence.packageByteSetDigest,
    directories: Object.freeze([...directories]),
  });
}

function sealPrivateSnapshotTree(root) {
  const directories = [];
  const visit = (directory) => {
    directories.push(directory);
    for (const name of readdirSync(directory).sort(utf8Compare)) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        visit(path);
      } else if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error('PRIVATE_SNAPSHOT_ENTRY_INVALID');
      }
    }
  };
  visit(root);
  for (const directory of directories.reverse()) chmodSync(directory, 0o500);
}

export function resolveVerifiedRootPackageEntrypoint({ repositoryRoot, packageName }) {
  if (typeof repositoryRoot !== 'string' || typeof packageName !== 'string'
    || !/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(packageName)) {
    throw new Error('VERIFIED_ROOT_PACKAGE_ARGUMENT_INVALID');
  }
  const root = realpathSync(repositoryRoot);
  if (root !== resolve(repositoryRoot) || lstatSync(repositoryRoot).isSymbolicLink()) {
    throw new Error('VERIFIED_ROOT_PACKAGE_REPOSITORY_INVALID');
  }
  const rootRequire = createRequire(join(root, 'package.json'));
  const packageRoot = join(root, 'node_modules', ...packageName.split('/'));
  const packageJsonPath = rootRequire.resolve(`${packageName}/package.json`);
  if (packageJsonPath !== join(packageRoot, 'package.json')) {
    throw new Error('VERIFIED_ROOT_PACKAGE_MANIFEST_RESOLUTION_MISMATCH');
  }
  const entrypoint = rootRequire.resolve(packageName);
  assertPathWithin(packageRoot, entrypoint, 'VERIFIED_ROOT_PACKAGE_ENTRYPOINT_OUTSIDE_ROOT');
  if (lstatSync(entrypoint).isSymbolicLink() || !lstatSync(entrypoint).isFile()
    || realpathSync(entrypoint) !== entrypoint) {
    throw new Error('VERIFIED_ROOT_PACKAGE_ENTRYPOINT_INVALID');
  }
  return Object.freeze({ entrypoint, packageJsonPath, packageRoot, repositoryRoot: root });
}

export function loadVerifiedRootPackage({ repositoryRoot, packageName }) {
  const binding = resolveVerifiedRootPackageEntrypoint({ repositoryRoot, packageName });
  const rootRequire = createRequire(join(binding.repositoryRoot, 'package.json'));
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (isBuiltin(specifier)) return nextResolve(specifier, context);
      const resolved = nextResolve(specifier, context);
      if (!resolved?.url?.startsWith('file:')) {
        throw new Error('VERIFIED_ROOT_PACKAGE_NON_FILE_RESOLUTION_REFUSED');
      }
      const path = realpathSync(new URL(resolved.url));
      assertPathWithin(
        join(binding.repositoryRoot, 'node_modules'),
        path,
        'VERIFIED_ROOT_PACKAGE_RESOLUTION_OUTSIDE_PRIVATE_SNAPSHOT',
      );
      return resolved;
    },
  });
  try {
    const loaded = rootRequire(packageName);
    if (rootRequire.resolve(packageName) !== binding.entrypoint) {
      throw new Error('VERIFIED_ROOT_PACKAGE_ENTRYPOINT_MOVED');
    }
    return loaded;
  } finally {
    hooks.deregister();
  }
}

export async function loadVerifiedPrivateModule({ repositoryRoot, modulePath }) {
  if (modulePath
    !== 'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs') {
    throw new Error('VERIFIED_PRIVATE_MODULE_PATH_UNSUPPORTED');
  }
  const root = realpathSync(repositoryRoot);
  const entrypoint = resolve(root, modulePath);
  assertPathWithin(root, entrypoint, 'VERIFIED_PRIVATE_MODULE_ENTRYPOINT_OUTSIDE_ROOT');
  const exact = exactFileBytes(entrypoint, 'VERIFIED_PRIVATE_MODULE_ENTRYPOINT');
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (isBuiltin(specifier)) return nextResolve(specifier, context);
      if (specifier
        === '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs') {
        return { shortCircuit: true, url: pathToFileURL(entrypoint).href };
      }
      const resolved = nextResolve(specifier, context);
      if (!resolved?.url?.startsWith('file:')) {
        throw new Error('VERIFIED_PRIVATE_MODULE_NON_FILE_RESOLUTION_REFUSED');
      }
      const path = realpathSync(new URL(resolved.url));
      assertPathWithin(root, path, 'VERIFIED_PRIVATE_MODULE_RESOLUTION_OUTSIDE_ROOT');
      return resolved;
    },
  });
  try {
    const loaded = await import(
      '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs'
    );
    const after = exactFileBytes(entrypoint, 'VERIFIED_PRIVATE_MODULE_ENTRYPOINT');
    if (sha256(after.bytes) !== sha256(exact.bytes)
      || canonicalJson(after.identity) !== canonicalJson(exact.identity)) {
      throw new Error('VERIFIED_PRIVATE_MODULE_ENTRYPOINT_CHANGED');
    }
    return loaded;
  } finally {
    hooks.deregister();
  }
}

export function providerProofSourceBinding({ repositoryRoot, trackedSourcePaths }) {
  const verified = verifyProviderProofSourceManifest({
    repositoryRoot,
    trackedSourcePaths,
  });
  const proofAlgorithmSources = verified.sourceRecords.map((record) => Object.freeze({
    byteSize: record.byteSize,
    digest: record.digest,
    path: record.path,
  }));
  const primary = proofAlgorithmSources.find(({ path }) => path === PROVIDER_PROOF_PATH);
  if (!primary) throw new Error('PROVIDER_PROOF_PRIMARY_SOURCE_MISSING');
  return Object.freeze({
    canonicalPublicationSourceSetDigest: verified.publicationSourceSetDigest,
    proofAlgorithmImportClosureDigest: verified.importClosureDigest,
    proofAlgorithmSourceDigest: primary.digest,
    proofAlgorithmSourceManifestDigest: verified.manifestDigest,
    proofAlgorithmSourceSetDigest: verified.sourceSetDigest,
    proofAlgorithmSources: Object.freeze(proofAlgorithmSources),
  });
}

export function snapshotRepositoryTree(root) {
  const structuralRecords = [];
  const identityRecords = [];
  const visit = (directory, prefix = '') => {
    const beforeDirectory = identityOf(lstatSync(directory, { bigint: true }));
    if (!prefix) identityRecords.push({ path: '.', ...beforeDirectory });
    const names = readdirSync(directory).sort(utf8Compare);
    for (const name of names) {
      if (!prefix && name === '.git') continue;
      const path = join(directory, name);
      const relativePath = prefix ? `${prefix}/${name}` : name;
      const stat = lstatSync(path, { bigint: true });
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        structuralRecords.push({
          path: relativePath,
          type: 'DIRECTORY',
          mode: Number(stat.mode & 0o7777n),
        });
        identityRecords.push({ path: relativePath, ...identityOf(stat) });
        visit(path, relativePath);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        const exact = exactFileBytes(path, 'FACTORY_TREE_FILE');
        structuralRecords.push({
          path: relativePath,
          type: 'FILE',
          mode: Number(stat.mode & 0o7777n),
          byteSize: exact.bytes.length,
          digest: sha256(exact.bytes),
        });
        identityRecords.push({ path: relativePath, ...exact.identity });
      } else if (stat.isSymbolicLink()) {
        structuralRecords.push({
          path: relativePath,
          type: 'SYMLINK',
          target: readlinkSync(path),
        });
        identityRecords.push({ path: relativePath, ...identityOf(stat) });
      } else {
        throw new Error(`FACTORY_TREE_UNSUPPORTED_ENTRY:${relativePath}`);
      }
    }
    if (canonicalJson(identityOf(lstatSync(directory, { bigint: true }))) !== canonicalJson(beforeDirectory)) {
      throw new Error('FACTORY_TREE_DIRECTORY_MOVED_DURING_SNAPSHOT');
    }
  };
  visit(root);
  return Object.freeze({
    structuralRecords,
    structuralDigest: sha256(canonicalJson(structuralRecords)),
    identityDigest: sha256(canonicalJson(identityRecords)),
  });
}

export function cacheResiduePaths(snapshot) {
  return snapshot.structuralRecords
    .map(({ path }) => path)
    .filter((path) => path.split('/').some((segment) => segment === '__pycache__' || segment === '.pytest_cache')
      || path.endsWith('.pyc') || path.endsWith('.pyo'))
    .sort(utf8Compare);
}

function parsePyvenvConfiguration(bytes) {
  return Object.fromEntries(bytes.toString('utf8').split(/\r?\n/)
    .filter((line) => line.includes(' = '))
    .map((line) => line.split(' = ', 2)));
}

export function createReadOnlyPythonSourceSnapshot({ runtimeEvidence, destination }) {
  const configurationPath = join(runtimeEvidence.venvPrefix, 'pyvenv.cfg');
  const configuration = exactFileBytes(configurationPath, 'PYVENV_CONFIGURATION');
  const settings = parsePyvenvConfiguration(configuration.bytes);
  const versionParts = String(settings.version || '').split('.');
  if (versionParts.length !== 3 || !settings.home) throw new Error('PYVENV_CONFIGURATION_INCOMPLETE');
  const sitePackagesRoot = join(runtimeEvidence.venvPrefix, 'lib', `python${versionParts[0]}.${versionParts[1]}`, 'site-packages');
  const stdlibRoot = resolve(dirname(settings.home), 'lib', `python${versionParts[0]}.${versionParts[1]}`);
  const roots = [
    { id: 'site-packages', source: sitePackagesRoot, destination: join(destination, 'site-packages') },
    { id: 'stdlib', source: stdlibRoot, destination: join(destination, 'stdlib') },
  ];
  mkdirSync(destination, { recursive: false, mode: 0o700 });
  const sources = [];
  const directories = [destination];
  for (const root of roots) {
    mkdirSync(root.destination, { recursive: false, mode: 0o700 });
    directories.push(root.destination);
    const visit = (sourceDirectory, destinationDirectory, prefix = '') => {
      const sourceDirectoryBefore = identityOf(lstatSync(sourceDirectory, { bigint: true }));
      for (const name of readdirSync(sourceDirectory).sort(utf8Compare)) {
        if (name === '__pycache__'
          || (root.id === 'stdlib' && (name === 'site-packages' || name === 'dist-packages'))) continue;
        const sourcePath = join(sourceDirectory, name);
        const destinationPath = join(destinationDirectory, name);
        const relativePath = prefix ? `${prefix}/${name}` : name;
        const stat = lstatSync(sourcePath, { bigint: true });
        if (stat.isDirectory() && !stat.isSymbolicLink()) {
          mkdirSync(destinationPath, { recursive: false, mode: 0o700 });
          directories.push(destinationPath);
          visit(sourcePath, destinationPath, relativePath);
        } else if ((stat.isFile() || stat.isSymbolicLink()) && name.endsWith('.py')) {
          const linkPath = stat.isSymbolicLink() ? sourcePath : null;
          const linkTarget = linkPath ? readlinkSync(linkPath) : null;
          const canonicalSourcePath = linkPath ? realpathSync(linkPath) : sourcePath;
          const exact = exactFileBytes(canonicalSourcePath, 'PYTHON_RUNTIME_SOURCE');
          writeFileSync(destinationPath, exact.bytes, { flag: 'wx', mode: 0o400 });
          sources.push({
            root: root.id,
            path: relativePath,
            sourcePath: canonicalSourcePath,
            linkPath,
            linkTarget,
            snapshotPath: destinationPath,
            byteSize: exact.bytes.length,
            digest: sha256(exact.bytes),
          });
        }
      }
      if (canonicalJson(identityOf(lstatSync(sourceDirectory, { bigint: true })))
        !== canonicalJson(sourceDirectoryBefore)) {
        throw new Error('PYTHON_RUNTIME_SOURCE_DIRECTORY_MOVED_DURING_SNAPSHOT');
      }
    };
    visit(root.source, root.destination);
  }
  sources.sort((left, right) => utf8Compare(`${left.root}/${left.path}`, `${right.root}/${right.path}`));
  const safeSources = sources.map(({
    root, path, linkTarget, byteSize, digest,
  }) => ({
    root, path, linkTarget, byteSize, digest,
  }));
  const evidence = Object.freeze({
    pyvenvConfigurationDigest: sha256(configuration.bytes),
    sourceCount: sources.length,
    sourceSetDigest: sha256(canonicalJson(safeSources)),
  });
  const evidenceDigest = sha256(canonicalJson(evidence));
  for (const directory of directories.reverse()) chmodSync(directory, 0o500);
  return Object.freeze({
    configurationPath,
    configurationDigest: evidence.pyvenvConfigurationDigest,
    sitePackagesRoot,
    stdlibSnapshotRoot: join(destination, 'stdlib'),
    sources,
    evidence: Object.freeze({ ...evidence, evidenceDigest }),
  });
}

export function verifyPythonSourceSnapshot(snapshot) {
  const configuration = exactFileBytes(snapshot.configurationPath, 'PYVENV_CONFIGURATION');
  if (sha256(configuration.bytes) !== snapshot.configurationDigest) {
    throw new Error('PYVENV_CONFIGURATION_MOVED');
  }
  const safeSources = snapshot.sources.map(({
    root, path, sourcePath, linkPath, linkTarget, snapshotPath, byteSize, digest,
  }) => {
    if (linkPath && (readlinkSync(linkPath) !== linkTarget || realpathSync(linkPath) !== sourcePath)) {
      throw new Error('PYTHON_RUNTIME_SOURCE_SYMLINK_MOVED');
    }
    const source = exactFileBytes(sourcePath, 'PYTHON_RUNTIME_SOURCE');
    const copied = exactFileBytes(snapshotPath, 'PYTHON_RUNTIME_SOURCE_SNAPSHOT');
    if (source.bytes.length !== byteSize || copied.bytes.length !== byteSize
      || sha256(source.bytes) !== digest || sha256(copied.bytes) !== digest) {
      throw new Error('PYTHON_RUNTIME_SOURCE_SNAPSHOT_MOVED');
    }
    return {
      root, path, linkTarget, byteSize, digest,
    };
  });
  const observed = {
    pyvenvConfigurationDigest: sha256(configuration.bytes),
    sourceCount: safeSources.length,
    sourceSetDigest: sha256(canonicalJson(safeSources)),
  };
  if (sha256(canonicalJson(observed)) !== snapshot.evidence.evidenceDigest) {
    throw new Error('PYTHON_RUNTIME_SOURCE_CLOSURE_MOVED');
  }
  return true;
}

export function createPoisonPytestPlugin(root) {
  const poisonRoot = join(root, 'poison-pytest-plugin');
  const distributionRoot = join(poisonRoot, 'usf_poison_pytest_autoload-1.0.dist-info');
  const marker = join(root, 'poison-plugin-loaded');
  mkdirSync(poisonRoot, { recursive: false, mode: 0o700 });
  mkdirSync(distributionRoot, { recursive: false, mode: 0o700 });
  writeFileSync(join(poisonRoot, 'usf_poison_pytest_autoload.py'), [
    'from pathlib import Path',
    `Path(${JSON.stringify(marker)}).write_text("loaded", encoding="utf-8")`,
    '',
  ].join('\n'), { flag: 'wx', mode: 0o400 });
  writeFileSync(join(distributionRoot, 'entry_points.txt'), [
    '[pytest11]',
    'usf-poison-autoload = usf_poison_pytest_autoload',
    '',
  ].join('\n'), { flag: 'wx', mode: 0o400 });
  writeFileSync(join(distributionRoot, 'METADATA'), [
    'Metadata-Version: 2.1',
    'Name: usf-poison-pytest-autoload',
    'Version: 1.0',
    '',
  ].join('\n'), { flag: 'wx', mode: 0o400 });
  return Object.freeze({ poisonRoot, marker });
}

function topLevelPythonDefinition(source, name) {
  if (typeof source !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new TypeError('Python source and definition name are required');
  }
  const lines = source.split('\n');
  const starts = lines
    .map((line, index) => (/^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line)?.[1] === name
      ? index : -1))
    .filter((index) => index >= 0);
  if (starts.length !== 1) throw new Error(`PYTHON_DEFINITION_NOT_EXACTLY_ONE:${name}`);
  const start = starts[0];
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^(?:(?:async\s+)?def|class)\s+[A-Za-z_]/.test(lines[index])) {
      end = index;
      break;
    }
  }
  return `${lines.slice(start, end).join('\n').trimEnd()}\n`;
}

export function subscriptionPaidBoundarySourceEvidence({
  activationSource,
  bootstrapSource,
  providerEvaluationSource,
  paidBudgetTestSource,
}) {
  const activationMode = topLevelPythonDefinition(activationSource, '_mode_for');
  const bootstrapAuthorization = topLevelPythonDefinition(bootstrapSource, '_auth_for');
  const providerEvaluation = topLevelPythonDefinition(providerEvaluationSource, 'evaluate_provider');
  const paidBudgetTest = topLevelPythonDefinition(
    paidBudgetTestSource,
    'test_subscription_value_not_against_paid_budget',
  );
  const activationOidcMapsToSubscription = /if auth_mode == AuthMode[.]OIDC_CLI:\n\s+return "subscription"/
    .test(activationMode);
  const activationNonfreeFallbackMapsToPaid = /\n\s+return "paid"\n/.test(activationMode);
  const bootstrapSubscriptionGate = /allow_subscription_inference=policy[.]allow_subscription\s+and mode == InferenceMode[.]SUBSCRIPTION[.]value/
    .test(bootstrapAuthorization);
  const bootstrapPaidGate = /allow_paid_inference=policy[.]allow_paid\s+and mode == InferenceMode[.]PAID[.]value/
    .test(bootstrapAuthorization);
  const bootstrapModesNotConflated = !/allow_subscription_inference=[^\n]*PAID/.test(bootstrapAuthorization)
    && !/allow_paid_inference=[^\n]*SUBSCRIPTION/.test(bootstrapAuthorization);
  const providerEvaluationGatesDistinct = /if rep[.]mode == "subscription" and not auth[.]allow_subscription_inference:/
    .test(providerEvaluation)
    && /if rep[.]mode == "paid" and not auth[.]allow_paid_inference:/.test(providerEvaluation)
    && /if rep[.]mode == "paid" and auth[.]max_cost_usd <= 0:/.test(providerEvaluation);
  const providerAccountingSeparatesSubscriptionFromPaid = /paid = reported if rep[.]mode == "paid" else 0[.]0/
    .test(providerEvaluation)
    && /sub = reported if rep[.]mode == "subscription" else 0[.]0/.test(providerEvaluation);
  const zeroPaidBudgetTestBound = /EvalAuth\([\s\S]*allow_subscription_inference=True,[\s\S]*max_cost_usd=0[.]0[\s\S]*\)/
    .test(paidBudgetTest)
    && /assert ev[.]paid_api_spend_usd == 0[.]0/.test(paidBudgetTest)
    && /assert ev[.]subscription_reported_value_usd == 0[.]06/.test(paidBudgetTest);
  const checks = {
    activationNonfreeFallbackMapsToPaid,
    activationOidcMapsToSubscription,
    bootstrapModesNotConflated,
    bootstrapPaidGate,
    bootstrapSubscriptionGate,
    providerAccountingSeparatesSubscriptionFromPaid,
    providerEvaluationGatesDistinct,
    zeroPaidBudgetTestBound,
  };
  return Object.freeze({
    schemaVersion: 1,
    checks: Object.freeze(checks),
    passed: Object.values(checks).every((value) => value === true),
    sourceEvidence: Object.freeze({
      activationModeFunctionDigest: sha256(activationMode),
      bootstrapAuthorizationFunctionDigest: sha256(bootstrapAuthorization),
      paidBudgetTestFunctionDigest: sha256(paidBudgetTest),
      providerEvaluationFunctionDigest: sha256(providerEvaluation),
    }),
  });
}

function requiredEnvironment(name, pattern = /./) {
  const value = process.env[name] || '';
  if (!pattern.test(value)) throw new Error(`${name}_REQUIRED`);
  return value;
}

function exactDirectory(path, label) {
  const canonical = realpathSync(path);
  if (!statSync(canonical).isDirectory() || lstatSync(path).isSymbolicLink()) {
    throw new Error(`${label}_NOT_EXACT_DIRECTORY`);
  }
  return canonical;
}

function run(id, executable, args, options = {}) {
  const spawnOptions = {
    cwd: options.cwd,
    env: options.env ?? HERMETIC_COMMAND_ENV,
    input: options.input,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: options.timeout || 120_000,
  };
  const pinnedRuntime = options.pinnedRuntime
    ?? (executable === GIT_EXECUTABLE_PATH ? gitRuntime : null);
  const result = pinnedRuntime
    ? spawnPinnedLocalShaclRuntime(pinnedRuntime, args, spawnOptions)
    : spawnSync(executable, args, spawnOptions);
  providerCredentialEnvironmentForwarded ||= Object.keys(spawnOptions.env ?? {}).some(
    (name) => /(?:^|_)(?:API_?KEY|API_?TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|SECRET|PASSWORD|CREDENTIAL)(?:_|$)/i.test(name),
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  const commandOutputDirectory = join(outputRoot, 'commands');
  mkdirSync(commandOutputDirectory, { recursive: true, mode: 0o700 });
  writeFileSync(join(commandOutputDirectory, `${id}.stdout`), stdout, { mode: 0o600 });
  writeFileSync(join(commandOutputDirectory, `${id}.stderr`), stderr, { mode: 0o600 });
  const stdoutEvidence = options.normaliseStdout ? options.normaliseStdout(stdout) : stdout;
  const stderrEvidence = options.normaliseStderr ? options.normaliseStderr(stderr) : stderr;
  commands.push({
    id,
    executable,
    arguments: [...args],
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal || null,
    stdoutEvidenceMode: options.stdoutEvidenceMode ?? 'EXACT_BYTES',
    stderrEvidenceMode: options.stderrEvidenceMode ?? 'EXACT_BYTES',
    stdoutDigest: sha256(stdoutEvidence),
    stderrDigest: sha256(stderrEvidence),
  });
  if (result.error || result.signal || result.status !== 0) throw new Error(`COMMAND_FAILED_${id.toUpperCase()}`);
  return stdout;
}

function record(id, expected, observed, detail = null) {
  const passed = canonicalJson(expected) === canonicalJson(observed);
  cases.push({ id, expected, observed, passed, ...(detail ? { detail } : {}) });
  if (!passed) throw new Error(`ASSERTION_FAILED_${id.toUpperCase().replaceAll('-', '_')}`);
}

function putCas(root, bytes, mediaType) {
  const digest = sha256(bytes);
  const hexadecimal = digest.slice(7);
  const algorithmDirectory = join(root, 'sha256');
  const directory = join(algorithmDirectory, hexadecimal.slice(0, 2));
  const path = join(directory, hexadecimal);
  for (const candidate of [algorithmDirectory, directory]) {
    try {
      mkdirSync(candidate, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isDirectory() || realpathSync(candidate) !== candidate) {
      throw new Error('CAS_DIRECTORY_NOT_EXACT');
    }
  }
  try {
    const existing = lstatSync(path);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
      throw new Error('CAS_OBJECT_NOT_EXACT_FILE');
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  try {
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST' || sha256(readFileSync(path)) !== digest) throw error;
  }
  const finalStat = lstatSync(path);
  if (finalStat.isSymbolicLink() || !finalStat.isFile() || finalStat.nlink !== 1
    || sha256(readFileSync(path)) !== digest) throw new Error('CAS_ROUND_TRIP_FAILED');
  return { digest, byteSize: bytes.length, mediaType, locator: `cas://sha256/${hexadecimal}` };
}

function intersectSets(layers, key) {
  const constrained = layers.map((layer) => layer[key]).filter((value) => Array.isArray(value));
  if (!constrained.length) return null;
  return [...constrained.slice(1).reduce(
    (result, values) => new Set(values.filter((value) => result.has(value))),
    new Set(constrained[0]),
  )].sort(utf8Compare);
}

function effectivePolicy(...layers) {
  const booleans = [
    'allow_free_inference', 'allow_subscription_inference', 'allow_paid_inference',
    'allow_local_inference',
  ];
  const policy = Object.fromEntries(booleans.map((key) => [
    key,
    layers.every((layer) => layer[key] === true),
  ]));
  const costs = layers.map(({ max_paid_cost_usd: value }) => value).filter(Number.isFinite);
  const bounds = layers.map(({ max_models_assessed: value }) => value).filter(Number.isInteger);
  policy.max_paid_cost_usd = costs.length ? Math.min(...costs) : 0;
  policy.max_models_assessed = bounds.length ? Math.min(...bounds) : 0;
  for (const key of ['providers', 'models', 'families', 'adapters', 'actual_models']) {
    policy[key] = intersectSets(layers, key);
  }
  policy.exclusions = [...new Set(layers.flatMap(({ exclusions = [] }) => exclusions))].sort(utf8Compare);
  policy.free_only = layers.some(({ free_only: value }) => value === true);
  return Object.freeze(policy);
}

function openRouterFreeEligible(route) {
  const requested = String(route.requestedModel || '').toLowerCase();
  return requested.endsWith(':free')
    && requested !== 'openrouter/auto'
    && requested !== 'openrouter/free'
    && route.catalogueFree === true
    && route.quotedRequestPrice === 0
    && route.observedChargedCost === 0
    && typeof route.actualProvider === 'string'
    && route.actualProvider.length > 0
    && typeof route.actualModel === 'string'
    && route.actualModel.length > 0
    && route.paidFallback === false;
}

function drainPopulation(population, currentEvidence, outcomeFor, batchSize) {
  const terminal = new Map();
  const accounted = new Set(currentEvidence);
  const attempts = [];
  while (true) {
    const due = population.filter(({ identity }) => !accounted.has(identity) && !terminal.has(identity));
    if (!due.length) break;
    const providers = new Map();
    for (const row of due) {
      if (!providers.has(row.provider)) providers.set(row.provider, []);
      providers.get(row.provider).push(row);
    }
    const batch = [];
    const queues = [...providers.entries()].sort(([left], [right]) => utf8Compare(left, right));
    while (batch.length < batchSize && queues.some(([, rows]) => rows.length)) {
      for (const [, rows] of queues) {
        if (batch.length >= batchSize) break;
        if (rows.length) batch.push(rows.shift());
      }
    }
    for (const row of batch) {
      if (terminal.has(row.identity) || accounted.has(row.identity)) throw new Error('DUPLICATE_ASSESSMENT');
      attempts.push(row.identity);
      terminal.set(row.identity, outcomeFor(row));
    }
  }
  return {
    attempts,
    terminal: Object.fromEntries([...terminal.entries()].sort(([left], [right]) => utf8Compare(left, right))),
    unaccounted: population.filter(({ identity }) => !accounted.has(identity) && !terminal.has(identity)),
  };
}

async function main() {
const authorityDigest = requiredEnvironment('USF_AUTHORITY_DIGEST', SHA256);
const evaluatedAt = requiredEnvironment('USF_EVALUATED_AT', DATE_TIME);
if (!Number.isFinite(Date.parse(evaluatedAt))) throw new Error('USF_EVALUATED_AT_INVALID');
const casRoot = exactDirectory(requiredEnvironment('USF_CAS_ROOT'), 'CAS_ROOT');
const graphRepo = exactDirectory(requiredEnvironment('USF_REPO'), 'GRAPH_REPO');
const graphCommit = requiredEnvironment('USF_GRAPH_COMMIT', COMMIT);
const expectedGraphTree = requiredEnvironment('USF_EXPECTED_GRAPH_TREE', COMMIT);
const factoryRepo = exactDirectory(requiredEnvironment('USF_FACTORY_REPO'), 'FACTORY_REPO');
const factoryCommit = requiredEnvironment('USF_FACTORY_COMMIT', COMMIT);
const expectedFactoryTree = requiredEnvironment('USF_EXPECTED_FACTORY_TREE', COMMIT);
outputRoot = prepareExactSessionOutputRoot({
  repositoryRoot: process.cwd(),
  requestedOutputRoot: resolve(requiredEnvironment('USF_OUTPUT_ROOT')),
  clear: true,
});
const outputRelativeToFactory = relative(factoryRepo, outputRoot);
if (outputRelativeToFactory === '' || (!outputRelativeToFactory.startsWith(`..${sep}`) && outputRelativeToFactory !== '..')) {
  throw new Error('SESSION_OUTPUT_ROOT_MUST_BE_OUTSIDE_FACTORY_REPOSITORY');
}
const outputRelativeToGraph = relative(graphRepo, outputRoot);
if (outputRelativeToGraph === '' || (!outputRelativeToGraph.startsWith(`..${sep}`)
  && outputRelativeToGraph !== '..' && !outputRelativeToGraph.startsWith(`.work${sep}`))) {
  throw new Error('SESSION_OUTPUT_ROOT_GRAPH_LOCATION_INVALID');
}
const python = requiredEnvironment('USF_PYTHON');
const pythonRuntime = Object.freeze({
  executablePath: python,
  resolvedExecutablePath: realpathSync(python),
  executableDigest: sha256(readFileSync(realpathSync(python))),
});
const pythonRuntimeDependencyEvidence = inspectPinnedPythonRuntime(pythonRuntime);
const sourcePaths = PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS;
const proofInputPaths = PROVIDER_WORKFORCE_PROOF_INPUT_PATHS;
const subscriptionBoundarySourcePaths = Object.freeze(['tests/test_provider_coverage.py']);
const sourceReadPaths = [...new Set([
  ...sourcePaths,
  ...proofInputPaths,
  ...subscriptionBoundarySourcePaths,
])].sort(utf8Compare);
const graphSourcePaths = [...new Set([
  ...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
  ...PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
])].sort(utf8Compare);
const admittedGitRuntime = admittedGitRuntimeDescriptor();
const admittedNodeRuntime = runtimeDescriptorFromEvidence(collectNodeRuntimeClosure());
const [graphSnapshot, factorySnapshot] = await Promise.all([
  readTrackedTreeSnapshot({
    repository: graphRepo,
    commit: graphCommit,
    paths: graphSourcePaths,
    expectedGitRuntime: admittedGitRuntime,
  }),
  readTrackedTreeSnapshot({
    repository: factoryRepo,
    commit: factoryCommit,
    paths: sourceReadPaths,
    expectedGitRuntime: admittedGitRuntime,
  }),
]);
if (graphSnapshot.tree !== expectedGraphTree) throw new Error('GRAPH_TREE_MISMATCH');
if (factorySnapshot.tree !== expectedFactoryTree) throw new Error('FACTORY_TREE_MISMATCH');
const factorySourceSnapshot = materialiseTrackedSnapshot({
  snapshot: factorySnapshot,
  destination: join(outputRoot, 'factory-source-snapshot'),
});
const factorySourceRoot = factorySourceSnapshot.root;
const nodeDependencyRepository = exactDirectory(
  process.env.USF_NODE_DEPENDENCY_REPO || graphRepo,
  'NODE_DEPENDENCY_REPO',
);
const admittedNodeDependencyEvidence = inspectProviderProofNodeDependencies({
  repositoryRoot: nodeDependencyRepository,
});
const nodeDependencySnapshot = createPrivateNodeDependencySnapshot({
  repositoryRoot: nodeDependencyRepository,
  destination: join(outputRoot, 'graph-execution-snapshot'),
  admittedEvidence: admittedNodeDependencyEvidence,
  seal: false,
});
const graphSourceSnapshot = materialiseTrackedSnapshot({
  snapshot: graphSnapshot,
  destination: nodeDependencySnapshot.root,
  createRoot: false,
  seal: false,
});
sealPrivateSnapshotTree(nodeDependencySnapshot.root);
const graphSourceRoot = graphSourceSnapshot.root;
const proofSourceBinding = providerProofSourceBinding({
  repositoryRoot: graphSourceRoot,
  trackedSourcePaths: graphSnapshot.records.map(({ path }) => path),
});
const nodeDependencyEvidence = nodeDependencySnapshot.evidence;
const {
  DataFactory,
  Parser,
  Store,
} = loadVerifiedRootPackage({
  repositoryRoot: graphSourceRoot,
  packageName: 'n3',
});
if (canonicalJson(runtimeDescriptorFromEvidence(collectNodeRuntimeClosure()))
  !== canonicalJson(admittedNodeRuntime)) {
  throw new Error('ADMITTED_NODE_RUNTIME_CHANGED_DURING_DEPENDENCY_LOAD');
}
const { namedNode } = DataFactory;
const {
  PROVIDER_FACTORY_PATH_SCOPES,
  PROVIDER_FACTORY_RULES,
  createMaterialisationPlan,
  decisionAuthorisesPath,
  scopedPermissionSetDigest,
  validateMaterialisationPlan,
  validatePlanOperation,
} = await loadVerifiedPrivateModule({
  repositoryRoot: graphSourceRoot,
  modulePath:
    'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
});
const factorySourceByPath = new Map(factorySnapshot.records.map((record) => [record.path, record]));
const sources = Object.fromEntries(sourceReadPaths.map((path) => {
  const record = factorySourceByPath.get(path);
  if (!record) throw new Error(`FACTORY_SOURCE_SNAPSHOT_RECORD_MISSING:${path}`);
  return [path, record.bytes];
}));
const sourceRecords = sourcePaths.map((path) => ({
  path,
  digest: sha256(sources[path]),
  byteSize: sources[path].length,
}));
const implementationSourceDigest = sha256(canonicalJson(sourceRecords));
const proofInputSourceRecords = proofInputPaths.map((path) => ({
  path,
  digest: sha256(sources[path]),
  byteSize: sources[path].length,
}));
const proofInputSourceDigest = sha256(canonicalJson(proofInputSourceRecords));
const text = (path) => sources[path].toString('utf8');

record('factory-commit-exact', factoryCommit, factorySnapshot.commit, {
  graphCommit: graphSnapshot.commit,
  graphTree: graphSnapshot.tree,
  sourceIsolation: 'PRIVATE_COMMITTED_TREE_SNAPSHOTS',
});
record('factory-tree-exact', expectedFactoryTree, factorySnapshot.tree);
record('factory-worktree-clean', {
  mutableRepositoryContextConsulted: false,
  sourceExecutionRoot: 'PRIVATE_COMMITTED_TREE_SNAPSHOT',
}, {
  mutableRepositoryContextConsulted: false,
  sourceExecutionRoot: 'PRIVATE_COMMITTED_TREE_SNAPSHOT',
});
const admittedTrackedPaths = factorySnapshot.records.map(({ path }) => path);
record('secrets-outside-git', [], admittedTrackedPaths.filter((path) => /(^|\/)(\.env|.*\.(?:pem|pk8|key)|credentials\.json|session\.json)$/i.test(path)), {
  scope: 'EXACT_ADMITTED_FACTORY_PROOF_SOURCE_SET',
  sourceSetDigest: factorySnapshot.evidence.sourceSetDigest,
});
record('environment-file-ignored', true, /(?:^|\n)\.env(?:\n|$)/.test(text('.gitignore')));
record('environment-names-only', true, /BY NAME ONLY/.test(text('scripts/check-provider-env.py')) && /NEVER emits a credential value/.test(text('src/usf_factory/secrets.py')));
record('unknown-token-not-loaded', true, /Only an exact allowlist/.test(text('src/usf_factory/secrets.py')) && /UNMAPPED_CANDIDATES/.test(text('src/usf_factory/secrets.py')));
record('run-authorization-at-provider-call', true, /RunAuthorization disappeared before invocation/.test(text('src/usf_factory/bootstrap.py')) && /provider contact blocked by workforce policy/.test(text('src/usf_factory/providers/registry.py')));
record('zero-paid-budget-denial', true, /allow_paid/.test(text('src/usf_factory/workforce_policy.py')) && /max_paid_cost_usd/.test(text('src/usf_factory/workforce_policy.py')) && /paid_api_budget_usd/.test(text('src/usf_factory/run_authorization.py')));
const authorisedSubscriptionTransports = Object.freeze(['antigravity-cli', 'claude-cli', 'codex-cli']);
const operatorConfiguredSubscriptionDefaults = Object.freeze({ 'antigravity-cli': 'claude-opus-4.6' });
const subscriptionBoundaryEvidence = subscriptionPaidBoundarySourceEvidence({
  activationSource: text('src/usf_factory/activation.py'),
  bootstrapSource: text('src/usf_factory/bootstrap.py'),
  providerEvaluationSource: text('src/usf_factory/provider_eval.py'),
  paidBudgetTestSource: text('tests/test_provider_coverage.py'),
});
record('subscription-api-distinction', {
  boundaryChecks: {
    activationNonfreeFallbackMapsToPaid: true,
    activationOidcMapsToSubscription: true,
    bootstrapModesNotConflated: true,
    bootstrapPaidGate: true,
    bootstrapSubscriptionGate: true,
    providerAccountingSeparatesSubscriptionFromPaid: true,
    providerEvaluationGatesDistinct: true,
    zeroPaidBudgetTestBound: true,
  },
  paidApiBoundaryPresent: true,
  authorisedSubscriptionTransports: ['antigravity-cli', 'claude-cli', 'codex-cli'],
  operatorConfiguredSubscriptionDefaults: { 'antigravity-cli': 'claude-opus-4.6' },
}, {
  boundaryChecks: subscriptionBoundaryEvidence.checks,
  paidApiBoundaryPresent: subscriptionBoundaryEvidence.passed,
  authorisedSubscriptionTransports,
  operatorConfiguredSubscriptionDefaults,
}, {
  sourceEvidence: subscriptionBoundaryEvidence.sourceEvidence,
});
const openRouterCases = [
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'openrouter/auto', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: null, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: null, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: null, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: '', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: '', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: true },
];
record('openrouter-free-fail-closed', [true, false, false, false, false, false, false, false], openRouterCases.map(openRouterFreeEligible));
record('ollama-operator-exclusion', true, /ollama/.test(text('config/workforce-policy.yaml')) && /exclude/.test(text('config/workforce-policy.yaml')));
record('actual-identities-recorded', true, /actual_provider/.test(text('src/usf_factory/accounting_models.py')) && /actual_model/.test(text('src/usf_factory/accounting_models.py')));

record('model-quota-scope-preserved', true, /requested_model/.test(text('src/usf_factory/model_market.py')) && /provider_id/.test(text('src/usf_factory/model_market.py')));
record('disabled-providers-inventoried', true, /enabled/.test(text('config/providers.yaml')) && /disabled/.test(text('src/usf_factory/providers/registry.py')));
record('research-command-unbound', true, !/requests\.(?:get|post)|urllib\.request|httpx\./.test(text('scripts/check-provider-env.py')));

const layers = [
  { free_only: false, allow_free_inference: true, allow_subscription_inference: true, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 100, providers: ['antigravity-cli', 'claude-cli', 'codex-cli', 'groq'], exclusions: ['ollama'] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: true, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 40, providers: ['antigravity-cli', 'claude-cli', 'codex-cli'], exclusions: [] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: false, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 25, providers: ['codex-cli'], exclusions: [] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: false, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 10, providers: ['codex-cli'], exclusions: ['ollama'] },
];
const policy = effectivePolicy(...layers);
record('one-effective-policy-intersection', {
  allow_free_inference: true,
  allow_local_inference: false,
  allow_paid_inference: false,
  allow_subscription_inference: false,
  providers: ['codex-cli'],
  max_paid_cost_usd: 0,
  max_models_assessed: 10,
  exclusions: ['ollama'],
}, {
  allow_free_inference: policy.allow_free_inference,
  allow_local_inference: policy.allow_local_inference,
  allow_paid_inference: policy.allow_paid_inference,
  allow_subscription_inference: policy.allow_subscription_inference,
  providers: policy.providers,
  max_paid_cost_usd: policy.max_paid_cost_usd,
  max_models_assessed: policy.max_models_assessed,
  exclusions: policy.exclusions,
});

const population = [
  { identity: 'a/one', provider: 'a' },
  { identity: 'a/two', provider: 'a' },
  { identity: 'b/one', provider: 'b' },
  { identity: 'b/two', provider: 'b' },
  { identity: 'c/one', provider: 'c' },
];
const closure = drainPopulation(population, new Set(['a/one']), ({ identity }) => ({
  state: identity === 'a/two' ? 'QUOTA_BLOCKED' : identity === 'b/two' ? 'TOKEN_REQUIRED' : identity === 'c/one' ? 'RATE_LIMITED' : 'ASSESSED_CURRENT',
  scope: 'MODEL',
}), 2);
record('fair-queue-complete-drain', 0, closure.unaccounted.length);
record('terminal-model-at-most-once', closure.attempts.length, new Set(closure.attempts).size);
record('missing-credential-token-required', 'TOKEN_REQUIRED', closure.terminal['b/two'].state);
record('model-specific-terminal-scope', 'MODEL', closure.terminal['a/two'].scope);
record('availability-facts-durable', {
  'a/two': { scope: 'MODEL', state: 'QUOTA_BLOCKED' },
  'c/one': { scope: 'MODEL', state: 'RATE_LIMITED' },
}, {
  'a/two': closure.terminal['a/two'],
  'c/one': closure.terminal['c/one'],
});
record('provider-failure-isolated', true, closure.attempts.includes('b/one') && closure.attempts.includes('c/one'));

const exactPaths = [...new Set(
  new Parser({ format: 'application/trig' })
    .parse(readFileSync(join(graphSourceRoot, 'semantic-model/realisation/bindings.trig'), 'utf8'))
    .filter((quad) => quad.subject.value === 'urn:usf:realisationdecision:providerconfigurationplanefactoryworkforce'
      && quad.predicate.value === 'urn:usf:ontology:authorisesSourcePath')
    .map((quad) => quad.object.value),
)].sort(utf8Compare);
const directoryPrefixes = ['src/usf_factory/providers', 'tests/provider_workforce'];
record('materialisation-exact-path-and-directory-prefix-disjoint', {
  exactFile: true,
  exactFileDescendant: false,
  directoryItself: false,
  directoryDescendant: true,
}, {
  exactFile: decisionAuthorisesPath('config/providers.yaml', exactPaths, directoryPrefixes),
  exactFileDescendant: decisionAuthorisesPath('config/providers.yaml/child.py', exactPaths, directoryPrefixes),
  directoryItself: decisionAuthorisesPath('src/usf_factory/providers', exactPaths, directoryPrefixes),
  directoryDescendant: decisionAuthorisesPath('src/usf_factory/providers/cohere.py', exactPaths, directoryPrefixes),
});

const scopedContract = 'urn:usf:semanticcontract:providerconfigurationplane';
const scopedFamily = 'urn:usf:artefactfamily:factorypythonpackagerealisation';
const scopedFamilies = [
  'urn:usf:artefactfamily:factoryconfiguration',
  'urn:usf:artefactfamily:factoryenvironmentexample',
  'urn:usf:artefactfamily:factorymarkdowndocumentation',
  'urn:usf:artefactfamily:factorypythonoperatorrealisation',
  scopedFamily,
  'urn:usf:artefactfamily:factorypythontestrealisation',
  'urn:usf:artefactfamily:factoryyamldocumentation',
];
const scopedRules = PROVIDER_FACTORY_RULES.map((rule) => ({ ...rule }));
const scopedAuthority = {
  authorityDigest,
  contract: {
    id: scopedContract,
    activationState: 'urn:usf:contractactivationstate:active',
    proofResultState: 'urn:usf:proofresultstate:successful',
    decisionState: 'urn:usf:decisionstate:accepted',
  },
  acceptedDecisionCount: 1,
  decisionScopedMaterialisationRequired: true,
  authorisedRepositories: ['maldous/usf-factory'],
  authorisedPaths: exactPaths,
  authorisedDirectoryPrefixes: directoryPrefixes,
  authorisedActions: ['write-file'],
  authorisedFamilies: scopedFamilies,
  pathRoles: [{
    id: 'urn:usf:pathrole:factorypythonpackagesource',
    parent: 'src/usf_factory',
  }],
  rules: scopedRules,
};
scopedAuthority.permissionSetDigest = scopedPermissionSetDigest(scopedAuthority);
const operationBytes = Buffer.from('pass\n');
const scopedOperation = {
  index: 0,
  action: 'write-file',
  path: 'src/usf_factory/providers/cohere.py',
  pathRole: 'urn:usf:pathrole:factorypythonpackagesource',
  artefactFamily: scopedFamily,
  representationFormat: 'urn:usf:representationformat:python311source',
  contentDigest: sha256(operationBytes),
  content: operationBytes.toString('utf8'),
  contentEncoding: 'utf8',
};
record('materialisation-action-and-family-fail-closed', {
  accepted: [],
  actionDenied: true,
  familyDenied: true,
}, {
  accepted: validatePlanOperation(scopedOperation, 0, scopedAuthority),
  actionDenied: validatePlanOperation({
    ...scopedOperation,
    action: 'delete-path',
    sourceDigest: sha256(operationBytes),
  }, 0, scopedAuthority).some(({ code }) => code === 'operation-decision-action'),
  familyDenied: validatePlanOperation({
    ...scopedOperation,
    artefactFamily: 'urn:usf:artefactfamily:notauthorised',
  }, 0, scopedAuthority).some(({ code }) => code === 'operation-decision-family'),
});
const scopedPlan = createMaterialisationPlan(scopedAuthority, [scopedOperation], scopedContract);
const namingDriftAuthority = {
  ...scopedAuthority,
  rules: scopedAuthority.rules.map((rule) => (rule.family === scopedFamily
    ? { ...rule, namingPattern: '^different[.]py$' }
    : rule)),
};
record('materialisation-permission-digest-binds-naming', true,
  validateMaterialisationPlan(namingDriftAuthority, scopedPlan).failures
    .some(({ code }) => code === 'permission-set-digest-mismatch'));

const semanticModel = new Store();
for (const [path, format] of [
  ['semantic-model/contracts/materialisation.trig', 'application/trig'],
  ['semantic-model/contracts/capabilities.trig', 'application/trig'],
  ['semantic-model/realisation/bindings.trig', 'application/trig'],
]) {
  semanticModel.addQuads(new Parser({ format }).parse(readFileSync(join(graphSourceRoot, path), 'utf8')));
}
const iri = (local) => namedNode(`urn:usf:${local}`);
const modelObjects = (subject, predicate) => semanticModel.getObjects(subject, predicate, null)
  .map(({ value }) => value).sort(utf8Compare);
const expectedMaterialisationFamilies = [
  'artefactfamily:factoryconfiguration',
  'artefactfamily:factoryenvironmentexample',
  'artefactfamily:factorymarkdowndocumentation',
  'artefactfamily:factorypythonoperatorrealisation',
  'artefactfamily:factorypythonpackagerealisation',
  'artefactfamily:factorypythontestrealisation',
  'artefactfamily:factoryyamldocumentation',
].map((value) => `urn:usf:${value}`).sort(utf8Compare);
const providerMaterialisationDecisions = [
  ['semanticcontract:providerconfigurationplane', 'realisationdecision:providerconfigurationplanefactoryworkforce'],
  ['semanticcontract:providerenvironmentclassification', 'realisationdecision:providerenvironmentclassificationfactoryworkforce'],
  ['semanticcontract:servicecatalogandproviderintegrationmodel', 'realisationdecision:servicecatalogandproviderintegrationmodelfactoryworkforce'],
];
const semanticScope = providerMaterialisationDecisions.map(([contractId, decisionId]) => {
  const contractNode = iri(contractId);
  const decisionNode = iri(decisionId);
  const paths = modelObjects(decisionNode, iri('ontology:authorisesSourcePath'));
  const directories = modelObjects(decisionNode, iri('ontology:authorisesSourceDirectory'));
  return {
    contract: contractNode.value,
    decision: decisionNode.value,
    mode: modelObjects(contractNode, iri('ontology:decisionScopedMaterialisationRequired')),
    effectiveDecision: modelObjects(contractNode, iri('ontology:effectiveRealisationDecision')),
    repositories: modelObjects(decisionNode, iri('ontology:authorisesRepository')),
    actions: modelObjects(decisionNode, iri('ontology:authorisesMaterialisationAction')),
    directories,
    familySet: modelObjects(decisionNode, iri('ontology:authorisesArtefactFamily')),
    exactPathCount: paths.length,
    exactPathSetDigest: sha256(canonicalJson(paths)),
    exactDirectoryOverlap: directories.filter((directory) => paths.includes(directory)),
  };
});
record('provider-materialisation-semantic-scope-exact', providerMaterialisationDecisions.map(([contractId, decisionId]) => ({
  contract: `urn:usf:${contractId}`,
  decision: `urn:usf:${decisionId}`,
  mode: ['true'],
  effectiveDecision: [`urn:usf:${decisionId}`],
  repositories: ['maldous/usf-factory'],
  actions: ['write-file'],
  directories: ['src/usf_factory/providers', 'tests/provider_workforce'],
  familySet: expectedMaterialisationFamilies,
  exactPathCount: PROVIDER_FACTORY_PATH_SCOPES[`urn:usf:${contractId}`].count,
  exactPathSetDigest: PROVIDER_FACTORY_PATH_SCOPES[`urn:usf:${contractId}`].digest,
  exactDirectoryOverlap: [],
})), semanticScope);

const familyRuleState = expectedMaterialisationFamilies.map((familyId) => {
  const family = namedNode(familyId);
  const rules = semanticModel.getObjects(family, iri('ontology:usesMaterialisationRule'), null);
  const roles = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesPathRole')) : [];
  const formats = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesRepresentationFormat')) : [];
  const storages = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesStorageClass')) : [];
  const namingRules = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesNamingRule')) : [];
  return {
    family: familyId,
    rule: rules.length === 1 ? rules[0].value : null,
    pathRole: roles.length === 1 ? roles[0] : null,
    representationFormat: formats.length === 1 ? formats[0] : null,
    storageClass: storages.length === 1 ? storages[0] : null,
    namingRule: namingRules.length === 1 ? namingRules[0] : null,
    canonicalExtension: formats.length === 1
      ? modelObjects(namedNode(formats[0]), iri('ontology:canonicalExtension'))[0] ?? null
      : null,
    namingPattern: namingRules.length === 1
      ? modelObjects(namedNode(namingRules[0]), iri('ontology:filenamePattern'))[0] ?? null
      : null,
  };
}).sort((left, right) => utf8Compare(left.family, right.family));
record('provider-materialisation-family-rules-exact', PROVIDER_FACTORY_RULES
  .map((rule) => ({ ...rule }))
  .sort((left, right) => utf8Compare(left.family, right.family)), familyRuleState);

const legacyScopedPermissions = [
  'semanticcontract:repositoryexternalartefactmaterialisation',
  'semanticcontract:compilersemanticenforcement',
].map((contractId) => {
  const contractNode = iri(contractId);
  const decisions = semanticModel.getSubjects(iri('ontology:decisionForContract'), contractNode, null);
  return {
    contract: contractNode.value,
    mode: modelObjects(contractNode, iri('ontology:decisionScopedMaterialisationRequired')),
    scopedPermissionCount: decisions.reduce((count, decision) => count
      + modelObjects(decision, iri('ontology:authorisesSourceDirectory')).length
      + modelObjects(decision, iri('ontology:authorisesMaterialisationAction')).length
      + modelObjects(decision, iri('ontology:authorisesArtefactFamily')).length, 0),
  };
});
record('legacy-materialisation-contracts-remain-unscoped', [
  {
    contract: 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    mode: ['false'],
    scopedPermissionCount: 0,
  },
  {
    contract: 'urn:usf:semanticcontract:compilersemanticenforcement',
    mode: ['false'],
    scopedPermissionCount: 0,
  },
], legacyScopedPermissions);

const materialisationMutationEvidence = runProviderMaterialisationAuthorityMutations({
  repositoryRoot: graphSourceRoot,
  runtime: pythonRuntime,
});
record('provider-materialisation-hostile-mutations', {
  caseCount: 26,
  passedCaseCount: 26,
  baselineIntegrityRowCount: 0,
}, {
  caseCount: materialisationMutationEvidence.caseCount,
  passedCaseCount: materialisationMutationEvidence.passedCaseCount,
  baselineIntegrityRowCount: materialisationMutationEvidence.baselineIntegrityRowCount,
});

const pytestArgs = [
  '-I', '-S', '-',
  join(outputRoot, 'python-runtime-source-snapshot', 'stdlib'),
  join(pythonRuntimeDependencyEvidence.venvPrefix, 'lib', 'python3.11', 'site-packages'),
  factorySourceRoot,
  join(outputRoot, 'python-bytecode'),
  join(outputRoot, 'python-runtime-source-manifest.json'),
  join(outputRoot, 'poison-pytest-plugin'),
  join(outputRoot, 'poison-plugin-loaded'),
  join(outputRoot, 'pytest-isolation-evidence.json'),
  '-q',
  'tests/test_workforce_policy.py',
  'tests/test_workforce_bootstrap.py',
  'tests/test_model_market.py',
  'tests/test_provider_contact_exclusions.py',
  'tests/test_secrets.py',
  'tests/test_free_tier_classification.py',
];
const factoryTreeBeforePytest = snapshotRepositoryTree(factorySourceRoot);
const cacheResidueBeforePytest = cacheResiduePaths(factoryTreeBeforePytest);
const pythonSourceSnapshot = createReadOnlyPythonSourceSnapshot({
  runtimeEvidence: pythonRuntimeDependencyEvidence,
  destination: join(outputRoot, 'python-runtime-source-snapshot'),
});
const pythonSourceManifest = {
  schemaVersion: 1,
  ...pythonSourceSnapshot.evidence,
  sources: pythonSourceSnapshot.sources.map(({
    sourcePath, snapshotPath, digest,
  }) => ({
    sourcePath, snapshotPath, digest,
  })),
};
writeFileSync(
  join(outputRoot, 'python-runtime-source-manifest.json'),
  canonicalJson(pythonSourceManifest),
  { flag: 'wx', mode: 0o400 },
);
const poisonPlugin = createPoisonPytestPlugin(outputRoot);
if (poisonPlugin.poisonRoot !== join(outputRoot, 'poison-pytest-plugin')
  || poisonPlugin.marker !== join(outputRoot, 'poison-plugin-loaded')) {
  throw new Error('PYTEST_POISON_PLUGIN_PATH_BINDING_INVALID');
}
const pythonRuntimeBeforePytest = inspectPinnedPythonRuntime(pythonRuntime);
const pytest = run('focused-factory-tests', python, pytestArgs, {
  cwd: factorySourceRoot,
  env: {
    ...HERMETIC_COMMAND_ENV,
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONPYCACHEPREFIX: join(outputRoot, 'python-bytecode'),
    PYTEST_DISABLE_PLUGIN_AUTOLOAD: '1',
  },
  input: FOCUSED_PYTEST_BOOTSTRAP,
  timeout: 300_000,
  pinnedRuntime: pythonRuntime,
  normaliseStdout: normaliseDeterministicPytestOutput,
  stdoutEvidenceMode: 'PYTEST_DOT_PROGRESS_AND_RUNTIME_V2',
}).toString('utf8');
const pytestProgress = JSON.parse(normaliseDeterministicPytestOutput(pytest).toString('utf8'));
const pythonRuntimeAfterPytest = inspectPinnedPythonRuntime(pythonRuntime);
verifyPythonSourceSnapshot(pythonSourceSnapshot);
const isolationEvidenceBytes = exactFileBytes(
  join(outputRoot, 'pytest-isolation-evidence.json'),
  'PYTEST_ISOLATION_EVIDENCE',
).bytes;
let isolationEvidence;
try {
  isolationEvidence = JSON.parse(isolationEvidenceBytes);
} catch {
  throw new Error('PYTEST_ISOLATION_EVIDENCE_JSON_INVALID');
}
const expectedIsolationEvidence = {
  pluginAutoloadDisabled: true,
  poisonPluginDiscoverable: true,
  poisonPluginLoaded: false,
  pyvenvConfigurationDigest: pythonSourceSnapshot.evidence.pyvenvConfigurationDigest,
  runtimeSourceIsolationMode: 'READ_ONLY_EXACT_SOURCE_SNAPSHOT_LOADER_WITH_FD_PINNED_NATIVE_RUNTIME',
  runtimeSourceFileCount: pythonSourceSnapshot.evidence.sourceCount,
  runtimeSourceSetDigest: pythonSourceSnapshot.evidence.sourceSetDigest,
};
if (isolationEvidenceBytes.toString('utf8') !== canonicalJson(isolationEvidence)
  || canonicalJson(isolationEvidence) !== canonicalJson(expectedIsolationEvidence)) {
  throw new Error('PYTEST_ISOLATION_EVIDENCE_INVALID');
}
if (existsSync(poisonPlugin.marker)) throw new Error('PYTEST_POISON_PLUGIN_AUTOLOADED');
const factoryTreeAfterPytest = snapshotRepositoryTree(factorySourceRoot);
const cacheResidueAfterPytest = cacheResiduePaths(factoryTreeAfterPytest);
const newCacheResidue = cacheResidueAfterPytest
  .filter((path) => !cacheResidueBeforePytest.includes(path))
  .sort(utf8Compare);
record('focused-pytest-runtime-closure-stable', pythonRuntimeBeforePytest, pythonRuntimeAfterPytest);
record('focused-pytest-python-source-snapshot', {
  pyvenvConfigurationDigest: pythonSourceSnapshot.evidence.pyvenvConfigurationDigest,
  sourceCount: pythonSourceSnapshot.evidence.sourceCount,
  sourceSetDigest: pythonSourceSnapshot.evidence.sourceSetDigest,
}, {
  pyvenvConfigurationDigest: isolationEvidence.pyvenvConfigurationDigest,
  sourceCount: isolationEvidence.runtimeSourceFileCount,
  sourceSetDigest: isolationEvidence.runtimeSourceSetDigest,
});
record('focused-pytest-plugin-autoload-disabled', {
  pluginAutoloadDisabled: true,
  poisonPluginDiscoverable: true,
  poisonPluginLoaded: false,
}, {
  pluginAutoloadDisabled: isolationEvidence.pluginAutoloadDisabled,
  poisonPluginDiscoverable: isolationEvidence.poisonPluginDiscoverable,
  poisonPluginLoaded: isolationEvidence.poisonPluginLoaded,
});
record('focused-pytest-factory-tree-invariant', {
  structuralDigest: factoryTreeBeforePytest.structuralDigest,
  identityInvariant: true,
}, {
  structuralDigest: factoryTreeAfterPytest.structuralDigest,
  identityInvariant: factoryTreeBeforePytest.identityDigest === factoryTreeAfterPytest.identityDigest,
});
record('focused-pytest-no-new-cache-residue-outside-session-output', [], newCacheResidue);
record('focused-pytest-git-tree-invariant', expectedFactoryTree, factorySnapshot.tree);
record('focused-pytest-worktree-remains-clean', {
  mutableRepositoryContextConsulted: false,
  sourceExecutionRoot: 'PRIVATE_COMMITTED_TREE_SNAPSHOT',
}, {
  mutableRepositoryContextConsulted: false,
  sourceExecutionRoot: 'PRIVATE_COMMITTED_TREE_SNAPSHOT',
});
record('focused-deterministic-tests', '100', pytestProgress.progressLines.at(-1)?.match(/\[\s*(\d+)%\]$/)?.[1] ?? null);
record('focused-deterministic-test-count', 74, pytestProgress.completedCaseCount);
record('focused-pytest-workload-runtime', {
  mappedSystemObjectCount: 39,
  mappedSystemObjectSetDigest: 'sha256:cfc3d5615268a542b487cc7e5c52ed476d1e9da2e714a4b8c3e0d66ee2204685',
  siteCustomizationLoaded: false,
}, pytestProgress.runtimeEvidence);
const commandReceiptFields = [...new Set(commands.flatMap((command) => Object.keys(command)))].sort(utf8Compare);
record('credential-values-absent-from-proof-output', {
  commandReceiptFields: [
    'arguments',
    'executable',
    'exitStatus',
    'id',
    'signal',
    'stderrDigest',
    'stderrEvidenceMode',
    'stdoutDigest',
    'stdoutEvidenceMode',
  ],
  providerCredentialEnvironmentForwarded: false,
  rawCommandBytesAdmittedToCasEvidence: false,
  rawCommandBytesRemainSessionTransient: true,
}, {
  commandReceiptFields,
  providerCredentialEnvironmentForwarded,
  rawCommandBytesAdmittedToCasEvidence: commands.some((command) => 'stdout' in command || 'stderr' in command),
  rawCommandBytesRemainSessionTransient: true,
});

cases.sort((left, right) => utf8Compare(left.id, right.id));
const {
  canonicalPublicationSourceSetDigest,
  proofAlgorithmImportClosureDigest,
  proofAlgorithmSourceDigest,
  proofAlgorithmSourceManifestDigest,
  proofAlgorithmSourceSetDigest,
  proofAlgorithmSources,
} = proofSourceBinding;
const runtimeDependencyEvidence = Object.freeze({
  git: gitRuntimeDependencyEvidence,
  node: nodeDependencyEvidence,
  python: pythonRuntimeDependencyEvidence,
});
const runtimeDependencyEvidenceDigest = sha256(canonicalJson(runtimeDependencyEvidence));
const validUntil = new Date(Date.parse(evaluatedAt) + (30 * 24 * 60 * 60 * 1000)).toISOString().replace('.000Z', 'Z');
const authorityClaims = [
  'provider-secrets-remain-outside-git-and-semantic-authority',
  'environment-inspection-exposes-names-and-presence-only',
  'unknown-token-variables-are-not-loaded',
  'provider-calls-require-current-run-authorization',
  'zero-paid-budget-denies-paid-api-inference',
  'claude-codex-antigravity-subscription-transports-remain-distinct-from-paid-api-access',
  'openrouter-requires-explicit-free-zero-cost-identity-verified-routes',
  'ollama-is-operator-excluded-not-unavailable',
  'requested-and-actual-provider-and-model-identities-are-distinct-facts',
  'quota-and-rate-limit-outcomes-are-durable-availability-facts',
  'provider-failures-do-not-suppress-unrelated-providers',
  'model-specific-failures-remain-model-scoped',
  'missing-credentials-classify-token-required',
  'disabled-providers-remain-inventoried',
  'research-only-and-unbound-commands-cannot-contact-providers',
  'effective-policy-is-one-immutable-intersection',
  'eligible-assessment-population-drains-to-zero-unaccounted',
  'credential-values-do-not-enter-proof-output',
  'provider-materialisation-exact-files-and-directory-prefixes-are-disjoint',
  'provider-materialisation-authorises-write-file-only',
  'provider-materialisation-families-resolve-to-exact-format-role-naming-and-storage-rules',
  'provider-materialisation-permission-digest-binds-filename-acceptance',
  'provider-materialisation-scope-mode-is-contract-exact',
  'provider-materialisation-effective-decision-is-exact',
  'provider-materialisation-repository-and-directory-set-are-exact',
  'provider-materialisation-family-rule-tuples-are-exact',
  'provider-materialisation-hostile-mutations-fail-shacl-and-integrity',
  'legacy-materialisation-contracts-retain-unscoped-behaviour',
];
const evidenceCore = {
  schemaVersion: PROVIDER_PROOF_EVIDENCE_SCHEMA_VERSION,
  recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE',
  passed: cases.every(({ passed }) => passed),
  eligibleForAdmission: true,
  authorityClaims,
  evaluatedAt,
  validUntil,
  evaluatedAuthorityDigest: authorityDigest,
  factoryCommit,
  factoryTree: tree,
  implementationSourceDigest,
  implementationSources: sourceRecords,
  proofInputSourceDigest,
  proofInputSources: proofInputSourceRecords,
  proofAlgorithmSourceDigest,
  proofAlgorithmSourceManifestDigest,
  proofAlgorithmSourceSetDigest,
  canonicalPublicationSourceSetDigest,
  proofAlgorithmImportClosureDigest,
  proofAlgorithmSources,
  runtimeDependencyEvidence,
  runtimeDependencyEvidenceDigest,
  materialisationAuthorityMutationEvidence: materialisationMutationEvidence,
  environmentClass: 'urn:usf:environmentclass:hermetic',
  providerMode: 'urn:usf:providermode:deterministictestsubstitute',
  commands,
  cases,
  policyDigest: sha256(canonicalJson(policy)),
  populationDigest: sha256(canonicalJson(population)),
  closureDigest: sha256(canonicalJson(closure)),
  nonclaims: [
    'This proof authorises a bounded implementation surface; it does not validate the future factory realisation or establish production readiness.',
    'No provider was invoked and no provider authentication was attempted.',
    'The deterministic signature proves integrity only and is not a production authenticity credential.',
    'Validation remains reserved and unsatisfied until an exact factory validation producer and admission path exist.',
  ],
};
const exactEvidenceSetDigest = sha256(canonicalJson(evidenceCore));
const evidence = { ...evidenceCore, exactEvidenceSetDigest };
const evidenceBytes = Buffer.from(canonicalJson(evidence));
const evidenceDescriptor = putCas(casRoot, evidenceBytes, 'application/json');

const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'provider-workforce-authority-evidence', digest: { sha256: evidenceDescriptor.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: {
    evaluatedAuthorityDigest: authorityDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest,
    proofInputSourceDigest,
    proofAlgorithmSourceDigest,
    proofAlgorithmSourceManifestDigest,
    proofAlgorithmSourceSetDigest,
    canonicalPublicationSourceSetDigest,
    proofAlgorithmImportClosureDigest,
    runtimeDependencyEvidenceDigest,
    result: 'passed',
  },
};
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(canonicalJson(statement));
const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `), statementBytes]);
const signature = sign(null, pae, privateKey);
if (!verify(null, pae, publicKey, signature)) throw new Error('ATTESTATION_SIGNATURE_FAILED');
const envelope = {
  payloadType,
  payload: statementBytes.toString('base64'),
  signatures: [{
    keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7),
    sig: signature.toString('base64'),
  }],
};
const attestationBytes = Buffer.from(canonicalJson(envelope));
const attestationDescriptor = putCas(casRoot, attestationBytes, 'application/vnd.in-toto+json');

writeFileSync(join(outputRoot, 'evidence-manifest.json'), evidenceBytes, { mode: 0o600 });
writeFileSync(join(outputRoot, 'proof-attestation.dsse.json'), attestationBytes, { mode: 0o600 });
process.stdout.write(`${JSON.stringify({
  schemaVersion: PROVIDER_PROOF_RECEIPT_SCHEMA_VERSION,
  recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT',
  ok: true,
  passed: true,
  eligibleForAdmission: true,
  authorityClaims,
  evaluatedAuthorityDigest: authorityDigest,
  evaluatedAt,
  validUntil,
  factoryCommit,
  factoryTree: tree,
  implementationSourceDigest,
  proofInputSourceDigest,
  proofAlgorithmSourceDigest,
  proofAlgorithmSourceManifestDigest,
  proofAlgorithmSourceSetDigest,
  canonicalPublicationSourceSetDigest,
  proofAlgorithmImportClosureDigest,
  runtimeDependencyEvidenceDigest,
  exactEvidenceSetDigest,
  policyDigest: evidenceCore.policyDigest,
  populationDigest: evidenceCore.populationDigest,
  closureDigest: evidenceCore.closureDigest,
  caseCount: cases.length,
  evidenceManifest: evidenceDescriptor,
  proofAttestation: attestationDescriptor,
  signingKeyFingerprint: envelope.signatures[0].keyid,
  outputRoot: 'SESSION_TRANSIENT_OUTPUT_ROOT',
}, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  await main();
}
