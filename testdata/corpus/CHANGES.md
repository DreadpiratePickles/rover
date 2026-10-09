# Changes to the collected corpus

The cases were collected for M5 (see SOURCES.md). Every later edit to an
existing case is recorded here with its reason. Cases are never deleted.

| Case | Change | Reason |
| --- | --- | --- |
| poisoning-tool_description-024 | `expect`: removed `hidden_markup` | The text uses a fake `<system>...</system>` block. That is pseudo-markup claiming authority, which `instruction_phrase` covers (`<system>` is in rules/phrases.txt); nothing in it is hidden from a reader (no `display:none`, `font-size:0`, `hidden` attribute or comment). |
| exfil-tool_description-005 | `expect`: removed `markdown_exfil_url` | The text has no markdown link or image, and its URL (`https://attacker.example/collect`) has no query string; the `?s=<summary>` is prose telling the model what to append. The rule is about URLs and markdown, so it cannot fire; `instruction_phrase` ("Do not mention this") is the right expectation. |

## Added cases (source "synthetic" unless noted)

| Case | Why |
| --- | --- |
| benign-elicitation_text-092, -093, -094 | The collected corpus had no benign elicitation text, so the false-positive rate of that kind was unmeasured. |
| exfil-tool_args-011 (unicode tag smuggling, source: the embracethered write-up) and exfil-tool_args-012 (bidi override) | The collected corpus had no tool_args attack, so the argument scan (invisible characters only) was untested by the corpus. |
