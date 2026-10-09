# M3 · The YAML → Cedar compiler

**Goal:** let you write policy in a short YAML file and have Rover turn it
into Cedar, without ever losing a rule on the way. Lesson focus: a compiler in
front of a security engine is part of the security boundary, and "strict or
refuse" beats "best effort".

## (a) What was built

In M2 you wrote policy in Cedar. Cedar is precise but wordy, and most rules
people want are of the form "this tool, only when that". M3 adds a small YAML
language for those rules (plan §5.4) and a compiler that turns it into Cedar:

```
 policy.yaml ──▶ yaml2cedar.Compile ──▶ Cedar text ──▶ policy.SchemaFor + policy.Load ──▶ Engine
   (you)          strict, line:col       (you can read it)   (M2's validator, unchanged)
```

- **`internal/policy/yaml2cedar`** reads the YAML as a tree of nodes
  (`gopkg.in/yaml.v3`, which remembers the line and column of every node) and
  checks every key against a fixed list. Anything it does not understand is a
  `*CompileError` like `policy.yaml:10:5: a rule: unknown key "alow"`. It never
  skips, guesses or approximates.
- **One Cedar policy per rule**, in order, each starting with `@id("<rule id>")`
  and a `// from <file>:<line>` comment, so a decision in the audit log
  (`rules=fs-read-projects`) leads straight back to the YAML line.
- **`rover policy compile <file.yaml>`** prints the Cedar. You learn Cedar by
  reading what your YAML became.
- **`rover policy validate`** accepts a `.yaml` (compiles, then validates, and
  prints both). `--print-schema` prints the schema actually in force.
- **`rover policy init --yaml`** writes `policy.yaml` instead of
  `policy.cedar`.
- **roverd load order:** `policy.cedar` if it exists, else `policy.yaml`
  (compiled at load), else nothing (`no_policy`: every policed message is
  blocked). The YAML's `mode`, `roots` and `labels` override `config.yaml`. A
  YAML that does not compile is logged with `file:line:col` and the previous
  policy (or none) stays in force.
- **The schema is generated** (carried over from M2). The M2 schema hard-coded
  a root named `projects` and made every argument *required*. Now
  `policy.SchemaFor` writes the `Args`, `Norm`, `NormPath` and `NormPaths`
  declarations from your roots and normalisers, and every attribute there is
  *optional*. A policy must ask `has` before reading one:
  `context.norm has path.under_lab && context.norm.path.under_lab`.

The conditions and what they compile to:

| YAML | Cedar |
| --- | --- |
| `allow: fs.read_file` | `permit (principal, action == Action::"call_tool", resource == Tool::"fs/read_file")` |
| `deny: "*"` | `forbid (principal, action, resource)`; `action == Action::"call_tool"` when a condition only exists for tool calls |
| `path_under: lab` | `context.norm has path.under_lab && context.norm.path.under_lab == true` |
| `session: {touched_private: true}` | `context.session.touched_private == true` |
| `tool_label: egress` | `resource.labels.contains("egress")` |
| `hour_between: [9, 18]` | `context.time.hour >= 9 && context.time.hour < 18` |
| `host_in: [a.org, b.org]` | `context.norm has url && ["a.org", "b.org"].contains(context.norm.url.host)` |
| `require: approval` | `@rover_require("approval")` (allow only) |
| `hide: true` | `@rover_hide("true")` (deny of one tool, no `when`) |

Several conditions in one `when` are joined with `&&`. After the rules, the
compiler adds one implied permit per server that has at least one `allow:`
rule, because an allowed tool is useless if the agent cannot see it in
`tools/list`:

```cedar
@id("echo-list-tools")
// implied: allow rules for echo need the agent to see the tool list
permit (principal, action == Action::"list_tools", resource == Server::"echo");
```

A server with only deny rules gets nothing, and a rule of your own with the
id `<server>-list-tools` is a compile error naming both lines.

## (b) Design decisions and the attacks they prevent

### 1. A compiler is part of the security boundary

Rover enforces the Cedar, not the YAML. Whatever the compiler drops never
reaches the engine. Picture a "friendly" compiler that ignores keys it does
not know, the way many config loaders do. You write:

```yaml
  - id: no-ssh-keys
    deny: filesystem.read_file
    wen: { path_under: ssh }      # typo
```

The friendly compiler drops `wen:`, and the rule becomes "deny read_file
everywhere". Annoying, but safe. Now the same typo on an allow rule turns
"read only inside projects" into "read anything". The operator looks at a
YAML that says one thing; the engine runs another. Nothing in any log shows
the difference. That gap is the attack surface.

### 2. Strict or refuse, never best effort

So every key is checked against a fixed list, everywhere: the top level, each
server, each rule, `when`, `session`. Unknown keys, unknown conditions,
unknown labels, duplicate keys, duplicate ids, YAML anchors and aliases, more
than one YAML document and `hour_between` that wraps past midnight are all
errors. The rule is: if there is no exact Cedar meaning, refuse. For example
`hour_between: [22, 6]` could be compiled as "22 to 24 OR 0 to 6", but that
is a guess about what you meant, so the compiler says
`not expressible as one rule, split the rule into [22, 24] and [0, 6]`.

### 3. Every error names a line and a column

A strict compiler is only bearable if it says exactly where you went wrong.
yaml.v3 keeps `Line` and `Column` on every node, so every error is
`file:line:col: message`, the same shape as a Go compiler error, and roverd's
log uses it too.

### 4. Restrict names, never escape them

A rule id goes inside `@id("...")`; a server and tool go inside
`Tool::"server/tool"`. If an id could contain `"` the YAML could close the
string and write Cedar of its own. One fix is escaping. Escaping is a parser
you have to get exactly right for every context (string, comment, entity id)
forever. Rover takes the other road: ids may only contain letters, digits,
`_`, `.` and `-`; servers and tools the same; hosts are lowercase DNS names;
roots are Cedar identifiers. None of those characters means anything in
Cedar, so there is nothing to escape. The file name in the `// from` comment
comes from your command line, not the YAML, but a newline in it would end the
comment, so control characters are replaced too.

### 5. `defaults: deny` and `version: 1` are required

Both are checked even though only one value is accepted. Writing
`defaults: deny` makes the reader of the YAML see the rule Rover applies
anyway. Requiring `version: 1` means a future format change cannot be read
by an old Rover as if it were the old format.

### 6. Every generated attribute is optional, so missing is `false`

In M2 the schema made `context.norm.path` required. A call without a path
made reading it an *evaluation error*. Cedar skips an erroring policy, so
Rover had to count an erroring forbid as fired (fail closed). That rule
stays, but errors are now rare: attributes are optional, and the validator
refuses any policy that reads one without a `has` test. The compiler emits
the `has` for you.

### 7. A `has` on an undeclared attribute is refused (found while building M3)

Cedar's validator gives `e has a` the type "always false" when the schema
says `e` cannot have `a`, and then it does not type-check the right side of
`&&` at all. So this passes Cedar validation when no root `lab` exists:

```cedar
forbid (...) when { context.norm has path.under_lab && context.norm.path.under_lab };
```

and the forbid can never fire. That is the "silently disabled forbid" strict
validation is supposed to prevent. Rover checks `has` itself because a forbid
that can never fire is fail-open: the operator believes something is blocked
and nothing is. Rover now checks every `has` itself
(`internal/policy/hascheck.go`) and refuses the policy:

```
error: policy load failed: compiled.cedar: policy "echo-read-lab" (line 12): `has under_lab` tests an attribute the schema does not declare there, so it is always false and the policy can never match (is a root or argument missing from the config?)
```

### 8. `policy.cedar` wins over `policy.yaml`

Two sources of truth are a trap. If both exist, roverd uses `policy.cedar`
and says so in its log once at start (`both policy.cedar and policy.yaml
exist: using policy.cedar (it wins); policy.yaml is ignored`). Hand-written
Cedar is the more specific, more powerful form, so it wins.

### 9. A YAML that does not compile changes nothing

On SIGHUP a broken YAML keeps the previous engine; at start it leaves roverd
with no policy, which blocks everything policed. Both are fail closed.

## (c) Exercise it by hand

```bash
make build
export ROVER_DIR=$(mktemp -d /tmp/rover-m3.XXXX)
./bin/rover policy init --yaml          # policy.yaml, config.yaml, schema, templates; no policy.cedar
C=$ROVER_DIR/config
```

Replace the starter with a policy for the echo server:

```bash
cat > $C/policy.yaml <<'EOF'
version: 1
mode: enforce
defaults: deny
servers:
  echo:
    labels: { read_file: [reads_private] }
roots: { lab: /tmp }
rules:
  - id: echo-call
    allow: echo.echo
  - id: echo-read-lab
    allow: echo.read_file
    when: { path_under: lab }
  - id: no-egress-after-private
    deny: "*"
    when: { session: { touched_private: true }, tool_label: egress }
EOF
printf 'servers:\n  echo:\n    read_file: { path: path }\n' > $C/normalizers.yaml
chmod 600 $C/normalizers.yaml
sed -i '' 's|^# normalizers: normalizers.yaml|normalizers: normalizers.yaml|' $C/config.yaml   # Linux: sed -i
echo 'hello from the lab' > /tmp/rover-m3-lab-note.txt
```

The rule and its Cedar side by side:

```yaml
  - id: echo-read-lab                      # line 11
    allow: echo.read_file
    when: { path_under: lab }
```

```
$ ./bin/rover policy compile $C/policy.yaml
...
@id("echo-read-lab")
// from /tmp/rover-m3-demo.hk2a/config/policy.yaml:11
permit (
  principal,
  action == Action::"call_tool",
  resource == Tool::"echo/read_file"
)
when {
  context.norm has path.under_lab && context.norm.path.under_lab == true
};
```

Validate, and look at the schema generated from the YAML's root:

```
$ ./bin/rover policy validate $C/policy.yaml
compiled /tmp/rover-m3-demo.hk2a/config/policy.yaml: 3 rules + 1 implied list_tools permits -> Cedar (mode enforce, roots: lab)
echo-call  permit
echo-read-lab  permit
no-egress-after-private  forbid
echo-list-tools  permit
ok: 4 policies (schema: /tmp/rover-m3-demo.hk2a/config/schema.cedarschema, generated for roots: lab)
$ ./bin/rover policy validate --print-schema | grep 'under_.*?:'
  under_lab?: Bool
  all_under_lab?: Bool
```

Start roverd with only `policy.yaml` present, and drive the echo server:

```
$ ./bin/rover daemon 2>daemon.log &
$ head -2 daemon.log
roverd policy precedence: no policy.cedar: compiling policy.yaml (its mode, roots and labels override config.yaml)
roverd policy loaded (mode enforce)
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi from yaml"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/rover-m3-lab-note.txt"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}' \
  | ROVER_TEST_NO_AUTOSTART=1 ./bin/rover wrap --name echo -- ./bin/echo-server
[rover] blocked request tools/call: no permit matched
{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Blocked by Rover policy (rule none): no permit matched. ..."}],"isError":true}}
{"jsonrpc":"2.0","id":1,"result":{...}}
{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"hi from yaml","type":"text"}]}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"hello from the lab\n","type":"text"}]}}
```

The block for id 4 is written straight back by the wrapper, so it arrives
before the server's answers to 1 to 3. Add
`'{"jsonrpc":"2.0","id":5,"method":"tools/list"}'` to the list and you get
echo's tools back: the compiler added `echo-list-tools` because the YAML has
allow rules for echo.

Stop roverd with `kill %1` when you are done.

## (d) Three attacks to try against it

### Attack 1: a typo a lenient compiler would silently drop

```
$ sed -i '' 's|    allow: echo.echo|    alow: echo.echo|' $C/policy.yaml
$ ./bin/rover policy compile $C/policy.yaml; echo "exit=$?"
error: /tmp/rover-m3-demo.hk2a/config/policy.yaml:10:5: a rule: unknown key "alow" (allowed: id, allow, deny, when, require, hide)
exit=1
$ ./bin/rover policy apply
$ tail -1 daemon.log
roverd policy reload FAILED, keeping the previous policy: /tmp/rover-m3-demo.hk2a/config/policy.yaml:10:5: a rule: unknown key "alow" (allowed: id, allow, deny, when, require, hide)
```

The echo call still works afterwards: the previous engine is in force. Try
the same typo in a `when` key (`wen:`), in `session` (`touched:`) and at the
top level (`rulez:`).

### Attack 2: a root that is not declared

```
$ sed 's|path_under: lab|path_under: secrets|' $C/policy.yaml > attack2.yaml
$ ./bin/rover policy compile attack2.yaml; echo "exit=$?"
error: attack2.yaml:13:25: path_under: root "secrets" is not declared under roots:
exit=1
```

Then try the Cedar route around the compiler: compile the good YAML to a
file and validate that file against a `config.yaml` without a `lab` root.
Cedar's own validator would accept it (see decision 7); Rover refuses it.

### Attack 3: rule id injection

```
$ cat attack3.yaml
version: 1
defaults: deny
rules:
  - id: 'x") ; permit(principal, action, resource); //'
    allow: echo.echo
$ ./bin/rover policy compile attack3.yaml; echo "exit=$?"
error: attack3.yaml:4:9: rule id "x\") ; permit(principal, action, resource); //": only letters, digits, _, . and - are allowed (at most 128, not starting with . or -); ids are restricted, never escaped
exit=1
```

Had the id been pasted into `@id("...")` unchecked, the output would have
contained a second, unconditional `permit (principal, action, resource);`,
allowing everything. Try the same trick through a server name
(`allow: 'echo"x.echo'`) and a host (`host_in: ['a.org"]']`).

## (e) Five explain-back questions

1. A lenient compiler that ignores unknown keys turns `alow: fs.read_file`
   into nothing. Why is that worse on an allow rule with a `when` than on a
   deny rule? Which way does each failure "fail"?
2. Why does Rover restrict rule ids to `[A-Za-z0-9_.-]` instead of escaping
   quotes? What would you have to get right, forever, if it escaped?
3. `hour_between: [22, 6]` has an obvious meaning. Why does the compiler
   refuse it instead of emitting two ranges joined by `||`?
4. Every `Norm` attribute is now optional. What did a missing argument do to
   a forbid in M2, what does it do now, and why does Rover still count an
   erroring forbid as fired?
5. Cedar's validator accepts `context.norm has path.under_lab && ...` when no
   `lab` root exists. Explain why the policy can then never match, why that
   is dangerous for a forbid but harmless for a permit, and what Rover added
   to stop it.
