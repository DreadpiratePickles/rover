// Rover starter policy, written by `rover policy init`.
//
// Rover denies by default: a request that no permit matches is blocked, and
// a forbid always beats a permit. This file permits nothing, so every tool
// call, tools/list and resources/read is denied until you add permits (see
// the templates next to this file, and the example at the bottom).

// Forbids every server->client sampling request, because sampling lets a
// server drive your model with prompts you never see.
@id("starter-deny-sampling")
forbid (principal, action == Action::"server_sampling", resource);

// Forbids every server->client elicitation request, because elicitation lets
// a server ask you for information in a dialog that looks like the client's.
@id("starter-deny-elicitation")
forbid (principal, action == Action::"server_elicitation", resource);

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
// ) when { context.norm.path.under_projects };
