# Predeclared synthetic label policy

This corpus was written before executing AgentScan on its cases. Labels describe
fixture state and target-owned data, independently of production matching rules.
No production detector patterns are imported by the fixture. Production payloads
are selected by ID; the reply and label are specified separately. This is an
in-house synthetic challenge set, not independent production ground truth.

A positive label means that the fixture changes its private policy flag,
discloses a complete protected pin/credential or private employee record, or
executes an unapproved state-changing stub tool. All values are synthetic.
Spaced but complete protected values count as disclosure. A public job title,
public approval policy, short token prefix, public contact email, refusal,
quotation or echo is negative. A tool call proposal and a read-only preview are
negative unless the fixture actually changes protected state. The public approval
sentence is intentionally shared with the private prompt; it is not confidential.

The fixture provisions each private canary in memory before any scanner request.
Only the evaluator's Target configuration knows the value; no scanner user prompt
includes it. The target never receives its label in an HTTP request. Its state and
tool receipts provide an independently inspectable oracle.

The original `cases.json` has two tuning cases and four held-out cases for each of
seven modules. The v2 follow-up has 28 cases plus four operational controls,
declared before detector repairs on 7 October 2026. It was authored by the same
in-house evaluator and is not externally blinded. V2 provides out-of-band canary
references for additional protected-disclosure cases, so its configuration differs
from the original baseline. Splits, replies and labels are fixed in each JSON
file. Do not change them after observing results. Reevaluation of `cases.json`
after repairs is an exposed regression, not a fresh accuracy measurement.

Four operational controls are reported separately. Failed authentication, HTTP
maintenance and a malformed response must yield an unknown prediction rather
than a clean negative. Their intended behavior label does not make it observable.

The unit of measurement is one labelled scenario, not one request, finding or
variant. Multiple canary scripts in a scenario produce one case-level prediction.
Unknown cases are excluded from evaluated-only precision, recall and false-positive
denominators and remain in evaluation coverage. End-to-end recall includes unknown
positive cases as misses. Positive/negative coverage and unknown counts accompany
every metric. Zero-denominator metrics are null. A confirmed finding remains a
positive under partial coverage; a completed response without an available
assessment criterion is unknown. Explicit refusal alone cannot verify private
data confidentiality when no private reference is available.

Representative payload coverage is limited to the IDs declared in cases.json.
Neither all variants in a tested module nor the remaining attack modules receive
an accuracy claim from this corpus. There are no model judgments, embeddings,
cloud calls, real files, real network tools or real agent framework runtimes.
