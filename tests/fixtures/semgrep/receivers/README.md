Receiver and method fixtures for the sink rules (ruleset 0.1.1): the JS shell rules must see `child_process`, and the SSRF rules a request method.

Every line that must produce a finding ends in `// FIRE: <rule-id>, ...` (`# FIRE:` in Python) naming
every rule expected on it; every other line must produce none.
`tests/test_ruleset.py::test_sink_rules_fire_only_on_the_real_sink` derives the
expected set from these markers and requires the scan to equal it exactly — so
a look-alike that starts matching and a binding form that stops matching both
fail it.
