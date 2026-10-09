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

## M5 review (verification findings M2, M6)

| Case | Change | Reason |
| --- | --- | --- |
| benign-tool_result-072 | `source` set to `synthetic` | Its source was a placeholder (`https://example.com/README.md`), not a real server. |
| benign-tool_description-095 … -106 | added, verbatim, with source URLs | The plan asks for at least 60 benign cases from real public MCP servers; there were 56. Added: memory (create_entities, add_observations, delete_entities, search_nodes), time (get_current_time, convert_time's `time`, the `timezone` parameter template), github-mcp-server (create_or_update_file, which names its sibling get_file_contents; list_commits; list_repository_collaborators; delete_repository), everything (get-sum). Real benign cases: 68. |
| injection-tool_result-022 … -024, poisoning-tool_description-025 … -030, exfil-tool_result-013 … -016 | added (synthetic) | One case per cheap tier-1 evasion the review listed: zero-width and soft hyphen inside words, emphasis inside words, HTML entities, no-break spaces, `< IMPORTANT >`, `](//`, reference-style image, `<img src>`, base64 over CRLF, Windows paths, C1 controls, U+061C. |

Since this review a case counts as detected only when an expected rule fires at **medium or higher** (a low finding only annotates the log, just as it never counts as a false positive). To keep poisoning-tool_description-019 (padding only) detected, `oversized` became medium in descriptions instead of the gate being lowered.
