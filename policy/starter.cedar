// Rover starter policy, written by `rover policy init`.
//
// Rover denies by default: a request that no permit matches is blocked, and
// a forbid always beats a permit. This file permits nothing, so every tool
// call, tools/list and resources/read is denied until you add permits (see
// the templates next to this file, and the example at the bottom). Its
// forbids stay in force after you add permits: sampling, elicitation, and
// egress once the session holds the lethal trifecta.

// Forbids every server->client sampling request, because sampling lets a
// server drive your model with prompts you never see.
@id("starter-deny-sampling")
forbid (principal, action == Action::"server_sampling", resource);

// Forbids every server->client elicitation request, because elicitation lets
// a server ask you for information in a dialog that looks like the client's.
@id("starter-deny-elicitation")
forbid (principal, action == Action::"server_elicitation", resource);

// The lethal trifecta guard (templates/trifecta-guard.cedar, active here).
// An agent that has (1) read private data, (2) seen text a stranger wrote
// and (3) a tool that can send data out can be talked into leaking (1)
// through (3) by instructions hidden in (2). Rover tracks (1) and (2) per
// agent session across every server, from tool labels:
//   - touched_private: a reads_private tool call succeeded,
//   - saw_untrusted: a reads_untrusted result arrived, or any result had a
//     medium or high detection finding.
// Labels come from the built-in list for well-known servers, then from
// config.yaml (which replaces them per tool), then from a CONSERVATIVE
// DEFAULT: a tool nobody labelled counts as reads_untrusted AND egress. So
// after a private read, an unknown tool's result taints the session and the
// next unknown tool is blocked as egress. Label your own tools in
// config.yaml to tell Rover what they really do; `rover policy labels`
// shows every label in force and where it came from.
// Do not also paste templates/trifecta-guard.cedar: the ids would clash.

// Forbids any egress tool once the session has both read private data and
// seen untrusted content, because that is exactly when injected instructions
// can send your data somewhere else.
@id("trifecta-no-egress")
forbid (principal, action == Action::"call_tool", resource)
when {
  context.session.touched_private &&
  context.session.saw_untrusted &&
  resource.labels.contains("egress")
};

// Forbids egress tools once the detector scores this call 70 or more,
// because a detected injection attempt is the strongest sign of an attack.
@id("trifecta-no-egress-after-detection")
forbid (principal, action == Action::"call_tool", resource)
when { resource.labels.contains("egress") && context.detection.max_score >= 70 };

// Example (uncomment to use): lets the filesystem server list its tools and
// read files, but only inside the root named "projects" in config.yaml,
// because norm.path is the path after "..", symlinks and look-alikes are
// resolved.
//
// @id("example-filesystem-list")
// permit (principal, action == Action::"list_tools", resource == Server::"filesystem");
//
// @id("example-filesystem-read-projects")
// permit (
//   principal,
//   action == Action::"call_tool",
//   resource in Server::"filesystem"
// ) when { context.norm has path.under_projects && context.norm.path.under_projects };
