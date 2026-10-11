# ATK-020: cross-agent workspace poisoning

ATK-020 explores whether poisoned shared-state content influences a target's
response. Its current scenarios simulate SQLite conversation history, a local
retrieval store and workspace instruction content.

## Supported behavior

The module prepares local scenario data and submits resulting context to the
configured target. Local retrieval can use optional embeddings or lexical
term-overlap fallback. These simulations do not prove that a customer's deployed
database, retrieval index or workspace file was ingested by another agent.

Use the normal scan, exploit or deep workflow described in the
[starting guide](../START_HERE.md), subject to that workflow's requirements and
target authorization. No deployed shared-state adapter is established by this
module's simulation.

## Interpret findings

Returned marker evidence is labeled as a **candidate**. Public markers included
in attack context can be echoed, so they do not prove private disclosure,
cross-agent propagation or execution. Review the evidence level and provenance
before treating a result as a confirmed exploit. Optional sandbox observations
describe their own bounded local execution.

To assess real shared-state behavior, instrument the actual write, retrieval and
downstream use boundaries, and define an independent expected outcome. Do not
infer deployed containment or successful compromise from simulated text alone.
