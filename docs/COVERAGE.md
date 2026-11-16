# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. No production source exclusions are currently approved.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

The planner's exit budget check was redundant: entry checks bound the sum;
reserve, release and refund transfer equal amounts; burns and debt repayment
reduce it; refill is capped by computed headroom. Other actions preserve it.
The same invariant is asserted over the native and wasm state partitions and
independently constrained by Noir. JSON Plan contains only primitive integers
and booleans, so encoding through serde_json::Value is total. No production
code is excluded from the report.

The source gate (`ccid coverage run`, configured by the [coverage] table of .ci/ccid.toml) cross-checks raw JSON counters, LCOV locations and LLVM's
annotated source inventory from the same execution. Every emitted source line
and branch must be covered, with no exclusions; raw instantiated counters remain
retained. A missing file, line, branch, ambiguous single-file report or inconsistent
summary refuses the gate. Committed lock policy is checked before refreshing
one snapshot. The single active CI group retains pending successors.
