<!--
MAINTAINER TODO (Bobby): the reporting link below only works once
"Private vulnerability reporting" is switched on for this repository:
GitHub → DreadpiratePickles/rover → Settings → Code security
(called "Code security and analysis" on some accounts) → Private vulnerability reporting → Enable.
Until then, the link returns an error and reporters have no private channel.
Delete this comment once it's enabled.
-->

# Security policy

Rover is a security tool. A bug in Rover can turn into a hole in every machine
that trusts it, so we treat vulnerability reports as the most important issues
we get. Thank you for taking the time to report one privately.

## Supported versions

Rover is pre-1.0. Only the latest release, and the `main` branch, get security
fixes. Older releases are not patched; upgrade instead.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| `main` | ✅ |
| Anything older | ❌ |

## How to report a vulnerability

**Do not open a public GitHub issue, discussion or pull request for a security
bug.** Public reports give attackers a head start on everyone who uses Rover.

Report privately through GitHub's private vulnerability reporting:

**<https://github.com/DreadpiratePickles/rover/security/advisories/new>**

Only the maintainers can see the report. We can discuss it with you there,
work on a fix in a private fork, and publish an advisory (with a CVE where it
makes sense) when the fix ships.

### What to include

The more of this you can give us, the faster we can act:

- **What's affected:** the component (see scope below), the Rover version or
  commit (`go version -m $(which rover)` prints it), and your OS and
  architecture.
- **What an attacker gains:** for example a policy bypass, an approval without
  the OS authentication dialog, a crash, data written somewhere it shouldn't be,
  or a secret leaked to a log.
- **Who the attacker is:** a malicious MCP server, injected content, an agent
  steered by injected content, a network attacker, and so on. Our threat model
  is in [`docs/IMPLEMENTATION_PLAN.md` §3](docs/IMPLEMENTATION_PLAN.md#3-threat-model).
- **Steps to reproduce:** ideally a minimal MCP server, message sequence, policy
  file or fuzz input that triggers it.
- **Your suggested fix**, if you have one. Not required.

Please don't include real secrets, tokens or personal data in the report. A
fake value that shows the leak is enough.

## What happens next

| Step | Target |
| --- | --- |
| We acknowledge your report | within **7 days** |
| We confirm or reject it, and tell you why | as soon as we can reproduce it |
| We share a fix or a mitigation plan | within **90 days** of the report |
| Public disclosure | coordinated with you, after a fix is available |

Rover is maintained by a small team, so these are targets, not guarantees. If
you haven't heard back in 7 days, please add a comment to your report.

We follow **coordinated disclosure**: we ask that you don't publish details
until a fix is released or 90 days have passed, whichever comes first. If a
vulnerability is being exploited in the wild, we'll move faster and may
publish a mitigation before the full fix. We're happy to credit you in the
advisory and release notes; tell us the name or handle you'd like used, or that
you'd rather stay anonymous.

## Scope

### In scope

- The `rover` binary and all its subcommands, including `rover wrap` (the
  per-server wrapper), `rover daemon` (**roverd**), `rover bridge` (remote MCP
  servers over HTTP), and the policy compilers.
- The client installers (`rover install` / `rover uninstall`) and anything they
  write to client configs or the system.
- **rover-net**: the tailnet policy tooling, controller and posture agent.
- Release artifacts and the build pipeline in this repository (for example, a
  way to get unreviewed code into a release).

Examples of what we especially want to hear about: a tool call that should have
been denied but was allowed; an approval granted without the OS authentication
dialog; a policy or audit log change made by something the agent can reach; a
wrapper that starts an MCP server when roverd is unreachable instead of failing
closed; a message that Rover inspects differently from how the server reads it;
a secret written to disk or to a log.

### Out of scope

These follow from Rover's threat model. They're real limits, not things we're
hiding:

- **Arbitrary malware running as the same user.** Code running with your user
  account can already do anything Rover can, including reading your files
  directly. Rover is not an endpoint protection product.
- **A same-user process killing roverd.** This is denial of service *by
  design*: when roverd is gone, wrappers fail closed and MCP servers don't run.
  That's not a bypass. (If you find a way to make a wrapper keep forwarding
  traffic *without* roverd's decision, that **is** in scope.)
- Attacks that need root or physical access to an unlocked machine.
- Vulnerabilities in third-party MCP servers, agent apps, Tailscale or
  Headscale themselves. Please report those to their maintainers. (A way those
  bugs get *through* Rover when its policy says they shouldn't is in scope.)
- Windows, which Rover doesn't support yet.
- Reports from automated scanners with no demonstrated impact.

## Safe harbor

If you research Rover in good faith, on machines, accounts and tailnets you own
or have permission to test, and you report what you find privately as described
here, we will not pursue or support legal action against you, and we'll
consider your research authorised. Don't access other people's data, don't
degrade services other people rely on, and stop and tell us if you
accidentally reach data that isn't yours.

## No bug bounty

Rover is an open-source project with no budget for a bug bounty. We can offer
public credit and our thanks.
