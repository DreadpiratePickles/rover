// Template: the official GitHub server may read but never write.

// Permits listing the GitHub server's tools, because the agent needs the list
// to know what it may call.
@id("gh-list-tools")
permit (principal, action == Action::"list_tools", resource == Server::"github");

// Permits the GitHub tools that only read, because reading code and issues
// is what an assistant needs most and cannot change anything.
@id("gh-read-tools")
permit (principal, action == Action::"call_tool", resource)
when {
  [
    Tool::"github/get_file_contents",
    Tool::"github/search_repositories",
    Tool::"github/search_code",
    Tool::"github/search_issues",
    Tool::"github/list_issues",
    Tool::"github/get_issue",
    Tool::"github/list_pull_requests",
    Tool::"github/get_pull_request",
    Tool::"github/list_commits"
  ].contains(resource)
};

// Forbids every GitHub tool labelled destructive in config.yaml, because a
// forbid still wins if someone later adds a broader permit by mistake.
@id("gh-forbid-destructive")
forbid (principal, action == Action::"call_tool", resource in Server::"github")
when { resource.labels.contains("destructive") };
