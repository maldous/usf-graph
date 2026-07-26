import { existsSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export function resolveContainedPath(root, path) {
  if (typeof path !== 'string' || path.length === 0) return { ok: false, reason: 'path must be a non-empty string' };
  // eslint-disable-next-line no-control-regex -- control characters are exactly what this guard rejects
  if (path.includes('\\') || path.includes('\0') || /[\x00-\x1f]/.test(path)) {
    return { ok: false, reason: 'path contains a forbidden separator or control character' };
  }
  if (isAbsolute(path) || path.startsWith('/')) return { ok: false, reason: 'path must be repository-relative' };
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    return { ok: false, reason: 'path contains an empty, current-directory, or parent-directory segment' };
  }
  const rootPath = resolve(root);
  const target = resolve(rootPath, ...segments);
  const fromRoot = relative(rootPath, target);
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    return { ok: false, reason: 'path escapes the output root' };
  }
  if (existsSync(target)) {
    const realRoot = realpathSync(rootPath);
    const realTarget = realpathSync(target);
    const realRelative = relative(realRoot, realTarget);
    if (realRelative === '..' || realRelative.startsWith(`..${sep}`) || isAbsolute(realRelative)) {
      return { ok: false, reason: 'path resolves through a link outside the output root' };
    }
    if (!statSync(target).isFile()) return { ok: false, reason: 'path does not identify a regular file' };
  }
  return { ok: true, target };
}
