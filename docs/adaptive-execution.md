# Observed-performance adaptive execution

## Claim boundary

Concurrency is a measured runtime decision, not configuration. The controller
starts at one after coordinator restart and has no configured worker target,
model slots, provider slots or fixed normal ceiling. `RunAuthorization` packet,
risk, budget and action limits still constrain *eligible work*; they are not
capacity estimates.

The timing and chosen load are intentionally nondeterministic. Packet identity,
snapshot, authority digest, repository base, fenced claim, authorization,
accounting and canonical integration order remain deterministic and auditable.

## Optimisation method

The selected controller combines marginal validated-throughput hill climbing,
continuous adjacent stochastic probes, rapid decrease after correctness or
capacity degradation, continuous resource-pressure penalties and downstream
backpressure. Emergency memory, swap, disk, thermal and allocation cutoffs are
safety stops only. They do not calculate normal worker capacity.

The deterministic simulation harness also evaluates additive-increase/adaptive-
decrease, sequential and every supplied fixed load. The hybrid is selected
because it optimises completed validated work, reacts when quality falls before
latency, distinguishes workload profiles, and continues bounded exploration
after apparent convergence.

## Observations

Decision history is separated by provider, actual/requested model, task and risk
class, context/output class, tool/mutation use and observed resource class. Each
invocation records, where observable:

- queue, first-token and total latency;
- output and input/cache tokens, output rate and provider/local cost facts;
- timeout, transport, throttle, truncation, malformed output, tool-call,
  incompleteness, scope and semantic-validation outcomes;
- retries/redraws and independent-review acceptance;
- CPU/load/run queue, memory/swap, GPU use/memory/temperature/allocation failure,
  disk/I/O, process and network observations;
- downstream integration/review/validation pressure.

Unknown sensors remain unknown. API success alone earns no validated-throughput
credit.

## Admission and recovery

SQLite `BEGIN IMMEDIATE` admission verifies the sole coordinator lease, packet
claim and both fencing tokens, then checks and increments the global active
invocation set. A unique partial index prohibits two active invocations for the
same packet. No conflicting packet set reaches dispatch. Completion and later
factory qualification are distinct append-only events.

After restart, the new coordinator fences prior active invocations, releases no
claim based on assumption, begins at one, and reacquires observations. A previous
optimum is historical evidence only. A replacement invocation is possible only
after durable reconciliation has made the prior attempt non-active.

## Protected actions

Exploration is prohibited for high/protected or mutating work, during recovery,
after coordinator uncertainty, and while downstream work is backlogged.
Adaptive execution never widens authorization, budget, egress, conflict or
protected-action policy. Merge and authority publication remain disabled while
their separately reported containment blockers exist.
