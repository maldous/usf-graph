// Source/live projection parity for every declared generator.
//
// A generator declares a `semanticInputQuery`. The generator answers it locally,
// against a scoped source dataset; the published semantic authority answers the
// same query against the complete managed dataset. If those two answers differ,
// the generated tree is a projection of a state that published authority does not
// hold — a graph subset chosen by a loader, not a semantic conclusion.
//
// This module runs both sides and fails closed on any disagreement. It also
// proves, rather than assumes, the `generation-input` scope's declared omission
// of review and derived graphs: if any generator's query result depended on
// them, the live answer would carry resources the local answer cannot, and the
// comparison would fail here.
//
// It performs no live-authority DECISION. It reads, compares and reports.

import { buildGenerationPlan } from './artefact-generation-plan.mjs';
import { generatorSelection } from './artefact-generation.mjs';

export const PROJECTION_PARITY_CODES = Object.freeze({
  missingLocally: 'generator-projection-missing-locally',
  missingLive: 'generator-projection-missing-live',
  queryUnsupported: 'generator-projection-query-unsupported',
  liveQueryFailed: 'generator-projection-live-query-failed',
});

const sortedUnique = (values) => [...new Set(values)].sort();

/**
 * Compare each declared generator's local projection with the published one.
 *
 * @param options.store the loaded source dataset
 * @param options.client a read-only live semantic authority client (`select`)
 * @returns a frozen report; `ok` is false when any generator disagrees.
 */
export async function compareGeneratorProjections({ store, client }) {
  const plan = buildGenerationPlan(store);
  const components = sortedUnique(plan.outputs.map((output) => output.component));
  const generators = [];
  const disagreements = [];

  for (const component of components) {
    let selection;
    try {
      selection = generatorSelection(store, component);
    } catch (error) {
      disagreements.push({ component, code: PROJECTION_PARITY_CODES.queryUnsupported, detail: error.message });
      generators.push({ component, comparable: false });
      continue;
    }
    const local = sortedUnique(selection.subjects.map((subject) => subject.value));

    let live;
    try {
      const rows = await client.select(selection.query);
      live = sortedUnique(rows.map((row) => row.resource?.value).filter(Boolean));
    } catch (error) {
      disagreements.push({ component, code: PROJECTION_PARITY_CODES.liveQueryFailed, detail: error.message });
      generators.push({ component, comparable: false, localCount: local.length });
      continue;
    }

    const liveSet = new Set(live);
    const localSet = new Set(local);
    const missingLive = local.filter((iri) => !liveSet.has(iri));
    const missingLocally = live.filter((iri) => !localSet.has(iri));
    for (const iri of missingLive) {
      disagreements.push({ component, code: PROJECTION_PARITY_CODES.missingLive, resource: iri });
    }
    for (const iri of missingLocally) {
      disagreements.push({ component, code: PROJECTION_PARITY_CODES.missingLocally, resource: iri });
    }
    generators.push({
      component,
      comparable: true,
      localCount: local.length,
      liveCount: live.length,
      agrees: missingLive.length === 0 && missingLocally.length === 0,
      semanticInputQuery: selection.query,
    });
  }

  return Object.freeze({
    ok: disagreements.length === 0,
    generatorCount: generators.length,
    comparedCount: generators.filter((item) => item.comparable).length,
    agreeingCount: generators.filter((item) => item.agrees).length,
    generators: Object.freeze(generators.map((item) => Object.freeze(item))),
    disagreements: Object.freeze(disagreements
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
      .map((item) => Object.freeze(item))),
  });
}

export async function assertGeneratorProjectionParity({ store, client }) {
  const report = await compareGeneratorProjections({ store, client });
  if (!report.ok) {
    const error = new Error(
      `generator projection parity failed for ${report.generatorCount - report.agreeingCount} of ${report.generatorCount} generators`,
    );
    error.report = report;
    throw error;
  }
  return report;
}
