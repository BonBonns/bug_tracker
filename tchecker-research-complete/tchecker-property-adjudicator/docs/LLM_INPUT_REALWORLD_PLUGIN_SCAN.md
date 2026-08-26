# LLM-input property: real plugin scan found and fixed two real bugs, then confirmed a correct result

Did a genuine from-scratch install (not just verifying the download URL) and scanned a real,
publicly-deployed RocketChat plugin that actually integrates with an LLM -- not a synthetic
fixture. This caught two real bugs in the producer script before it could be trusted, then
confirmed a correct, well-formed, hand-verified result.

## The install itself surfaced a real README bug
`joern --version` does not exit -- it silently ignores `--version` as an unrecognized flag,
prints the standard startup banner regardless, and drops into an interactive REPL waiting for
input. In a genuinely fresh sandbox following the README literally, this would hang, not confirm
anything. Corrected: verification should pipe input (forcing EOF) rather than expect the process
to exit on its own, and should not treat "--version" as a meaningful flag.

## The plugin: Rocket.Chat.App-Gemini
A real, small (2 TypeScript files), publicly available RocketChat App
(github.com/namnguyenthanhwork/Rocket.Chat.App-Gemini) that calls Google's Gemini API via
RocketChat's generic `IHttp.post()` client -- not a named SDK like the OpenAI or Anthropic
clients this property's producer was originally built to recognize.

## Hand-analysis before running the scanner, so the tool's output could be checked against
## something independent
Read the actual source directly. Two things to check, matching the property's two shapes:
- LLM01 Prompt Injection: the API call's `contents` array has exactly one message, `role: 'user'`
  -- no system role at all. Correctly not a candidate (sending user input in the user role is the
  intended, normal use).
- LLM02 Insecure Output Handling: the model's response (`geminiResponse`) only flows into
  `.setText()` on a RocketChat message builder -- not eval/exec/SQL/an HTML response/a redirect.
  Correctly not a candidate (no dangerous sink is fed).
Expected result: a genuine negative -- but only if the tool actually recognizes the LLM call site
in the first place, which is a separate question from correctly judging it safe.

## Bug 1: the LLM call site was not recognized at all
First scan produced three empty fact files. Not "correctly judged safe" -- the producer's
`llmProvider()` function only recognized OpenAI/Anthropic SDK method names, three named AI-SDK
functions, LangChain's `.invoke()/.call()`, and `fetch()` specifically to `api.openai.com` or
`api.anthropic.com`. RocketChat's `http.post(url, ...)` to
`generativelanguage.googleapis.com` matched none of these -- a real, documented blind spot (the
script's own header comment says as much: "a bespoke HTTP wrapper is missed"), now confirmed
against real, deployed code rather than left as an assumed limitation.

Fixed by adding a `resolvesToKnownLlmDomain()` check: for `post`/`get`-named calls, trace the URL
argument back to its defining assignment within the same method (RocketChat's pattern builds the
URL separately, not inline) and check whether it contains a known LLM provider domain. Verified
the tracing logic in isolation against the real CPG before trusting it (confirmed it correctly
resolves `url` to the template-literal assignment containing the Gemini domain).

## Bug 2: a second, independent whitelist silently dropped the fact even after Bug 1's fix
Re-ran after fixing Bug 1 -- still empty. A second, separate call-name whitelist
(`"create"|"generateText"|"streamText"|"generateObject"|"invoke"|"call"|"fetch"`), unconnected to
`llmProvider()`'s own logic, gates whether the fact row gets written at all. `"post"` was not in
this list, so the row was computed correctly and then silently discarded. Fixed by adding
`"post"` and `"get"` to this second whitelist too -- a real, separate bug from Bug 1, not the same
fix applying twice.

## Verified both fixes are correctly additive, not just locally correct
Re-ran the producer against its own regression fixture (six real cases: eval-vuln, sysinject-vuln,
output-safe, userrole-safe, no-llm, twilio-safe) after each fix. `gate_llm_input.py` still reports
7/7 PASS both times -- the extensions did not change behavior for any case they weren't meant to
affect.

## The final, correct result -- confirmed against real code, not just re-run
    llm_call_sites.tsv: commands/GeminiCommand.ts, line 26, provider=generic-http-llm
    llm_output_sinks.tsv: empty
    prompt_injection.tsv: empty

    llm_input_verdict.derive() output:
    {
      "schema": "llm-input-verdict/0.1",
      "findings": []
    }

Matches the hand-analysis exactly: the LLM call is now correctly detected (Bug 1 and 2 fixed), and
both vulnerability shapes are correctly, accurately determined to be absent -- not because the
tool failed to look, but because it looked and correctly found nothing there.

## Status
Two real bugs found by testing against real, deployed code rather than only synthetic fixtures,
both fixed, both re-verified against the existing regression fixture for no side effects, and the
real plugin's final result independently cross-checked against a hand-derived read of its actual
source. This is the same standard applied throughout this project: a scanner that only ever sees
its own fixtures can look correct while missing real-world shapes its fixtures never exercised.
