// SPARQL read-only guard for the USF MCP surface.
//
// Classifies a SPARQL string as a read-only query form (SELECT / ASK /
// CONSTRUCT / DESCRIBE) or a mutation, and rejects mutations. It fails closed:
// anything not provably a read-only query is refused.
//
// Detection strips IRIrefs, string literals and comments first, so a mutation
// keyword hiding inside a literal ("please DELETE") or a comment cannot make a
// read query look like an update, and a mutation cannot smuggle itself past by
// wrapping keywords in a string.

const READ_FORMS = new Set(['SELECT', 'ASK', 'CONSTRUCT', 'DESCRIBE']);
// SPARQL 1.1 Update operations. Any of these appearing as a bare keyword is a
// mutation and is rejected.
const MUTATIONS = new Set([
  'INSERT', 'DELETE', 'LOAD', 'CLEAR', 'DROP', 'CREATE', 'COPY', 'MOVE', 'ADD', 'WITH', 'UPDATE',
]);

function strip(sparql) {
  return sparql
    .replace(/<[^>]*>/g, ' ')            // IRIrefs
    .replace(/"""[\s\S]*?"""/g, ' ')     // triple-quoted "
    .replace(/'''[\s\S]*?'''/g, ' ')     // triple-quoted '
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')  // "..."
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')  // '...'
    .replace(/#[^\n]*/g, ' ');           // # line comments
}

// ponytail: contiguous-letter tokenisation means a prefixed local name that
// merely *contains* a keyword (usf:createdAt -> CREATEDAT) is safe; only a bare
// token equal to a keyword matches. A local name identical to a keyword
// (usf:create, ?add) false-positives and is refused — fail-closed, acceptable.
export function classifySparql(sparql) {
  if (typeof sparql !== 'string' || sparql.trim() === '') {
    return { readOnly: false, reason: 'empty query' };
  }
  const tokens = strip(sparql).toUpperCase().match(/[A-Z]+/g) || [];
  const mutation = tokens.find((t) => MUTATIONS.has(t));
  if (mutation) return { readOnly: false, reason: `mutation keyword ${mutation} rejected` };
  const form = tokens.find((t) => READ_FORMS.has(t));
  if (!form) return { readOnly: false, reason: 'not a SELECT/ASK/CONSTRUCT/DESCRIBE query' };
  return { readOnly: true, form };
}
