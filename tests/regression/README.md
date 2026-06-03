# TRUDI Regression Harness

Detects prompt regressions by replaying cases through TRUDI and scoring
the resulting trace against a hand-curated ground truth.

## Workflow

1. **Author a `ground_truth.json`** for the case at `<case_dir>/ground_truth.json`.
   Schema (see `tools/accuracy.py:accuracy_compare`):

   ```json
   {
     "case_id": "NITROBA-2008",
     "case_question": "Who sent the harassing email to lilytuckrige@yahoo.com?",
     "expected_findings": [
       {
         "id": "F1",
         "description": "<text that the trace finding should resemble>",
         "confidence_min": "CONFIRMED",
         "category": "attribution"
       }
     ],
     "negative_assertions": [
       "<claims that should NOT appear in the trace>"
     ]
   }
   ```

2. **Run the case in TRUDI** end-to-end (any client — Claude Code, custom
   agent, manual replay). The case produces `<case_dir>/analysis/<case>_trace.json`.

3. **Score the run**:

   ```bash
   python -m tests.regression.run_case \
       --case-dir /home/trin/cases/<case> \
       --ground-truth /home/trin/cases/<case>/ground_truth.json
   ```

   Exit code 0 if precision/recall meet the configured thresholds, 1 otherwise.
   Detailed output to stdout (true positives, false negatives, confidence
   downgrades).

4. **CI integration**: run all cases under `/home/trin/cases/*/` that
   have a `ground_truth.json`, fail the build on any regression.

## Why this exists

Prompt changes can fix one failure mode and silently break another. The
regression harness gives you a deterministic way to confirm that every
known case still resolves correctly after a `CLAUDE.md` / `_*_SYS` edit.

## Adding a case

1. Run the case once and confirm the trace is correct
2. Extract the key findings into `ground_truth.json` using the schema above
3. Include the `case_question` so the case-question gate is testable
4. Include `negative_assertions` for any claim known to be a hallucination
   in earlier prompt versions (so future prompt regressions trip)
5. Commit the ground_truth file under the case directory
