# Gate 14 build/run verification

- Full detector rebuild: PASS (`javac`, 2 existing deprecation warnings, zero errors).
- Real engine execution with gate disabled: PASS.
- Real engine execution with hard Gate-11 summary only: PASS.
- Real engine execution with hard + uncertain Gate-14 summaries: PASS.
- Uncertain loader: 4 loaded, 0 rejected.
- Uncertain fixed point: 7 functions, 2 rounds.
- Automated Gate-14 assertions: 10/10 PASS.

The Gate-14 channel is opt-in through `WP_FRONTEND_STATE_RETURN_UNCERTAIN`. With that variable absent, no MAY summaries are loaded or printed by the probe.
