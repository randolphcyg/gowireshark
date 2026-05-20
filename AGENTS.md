# gowireshark Agent Rules

`gowireshark` is the core libwireshark-backed SDK. Keep this repository focused on reusable packet-dissection primitives.

## Boundaries

- Wrap libwireshark capabilities behind stable Go APIs.
- Do not add CLI command handling, HTTP server behavior, Agent prompts, RAG logic, Zeek logic, or IDE-specific integration here.
- Prefer small, composable APIs that can support CLI, server, and Agent layers without depending on them.

## Engineering Rules

- Treat frame numbers as 1-based Wireshark frame numbers unless an API explicitly says otherwise.
- For large captures, prefer iterator, writer, session cache, or field-only paths over full in-memory frame trees.
- Keep errors stable where callers need to branch on them.
- Do not introduce hidden global Wireshark state that can leak across sessions or tests.

## Validation

Run before handing off SDK changes:

```bash
go test ./...
```
