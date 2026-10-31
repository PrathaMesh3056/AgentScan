# ATK-010 authored conversation contracts, v1

Frozen before execution on 31 October 2026. The case manifest fixes expected
request, evaluated-script and finding counts. Changes require a new method
version and preserved historical receipts. These are fixed-response engineering
controls, not model generations, attack-effectiveness measurements or customer
accuracy estimates. The author could read the public implementation contract.

Each arm selects the six production scripts. An intercepted HTTP service reads
the actual ordered user/assistant history. The private arm returns an independently
chosen synthetic reference on turn three; the budget arm returns it on turn one.
Public arms return ordinary public text or the historical public success marker.
Incomplete replies carry `done:false`. Missing/supplied-reference arms must send
no requests. Authentication returns HTTP 401 and must stop further dispatch.
Incomplete replies may proceed to the next isolated script, but never the next
turn of the affected script. Counts in the manifest are the predeclared oracle.

The fixture checks contiguous history roles, previous public answers, history
reset and absence of its private reference in delivered requests. A finding must
stop that script before the private reply can be replayed as input. Model
completion is patched to fail on any call. All HTTP is intercepted by `respx`;
no external target or local listening socket is required.

Run `python -m benchmarks.evaluation.atk010_run --output NEW_DIRECTORY`.
The runner refuses an existing directory. It records source/corpus/manifest hashes,
actual counters, bounded public report metadata and a pass gate, omitting raw
references and responses. Failed gates remain saved. Keep output under an ignored
local directory such as `.test-tmp/`. Separate regressions exercise transport,
provenance, completion, cancellation and SDK privacy boundaries.

No defense is installed. Benign model utility, fresh positive real-agent evidence,
adaptive attack comparisons and defense benefit remain deferred; authored public
replies cannot measure them.
