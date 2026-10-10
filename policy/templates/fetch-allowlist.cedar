// Template: the official fetch server may only fetch from listed hosts.

// Permits listing the fetch server's tools, because the agent needs the list
// to know what it may call.
@id("fetch-list-tools")
permit (principal, action == Action::"list_tools", resource == Server::"fetch");

// Permits fetching over HTTPS from the hosts listed here only, because
// norm.url.host is the lowercased host with userinfo rejected, so tricks like
// "https://docs.python.org@evil.example" cannot pass. Edit the list.
@id("fetch-allowed-hosts")
permit (principal, action == Action::"call_tool", resource == Tool::"fetch/fetch")
when {
  context.norm has url &&
  context.norm.url.scheme == "https" &&
  ["docs.python.org", "pkg.go.dev", "developer.mozilla.org"].contains(context.norm.url.host)
};
