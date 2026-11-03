// Template: egress tools may only reach the hosts listed here (M10).
//
// DLP blocks a call whose arguments carry a credential, but data does not
// need to look like a key to be worth stealing. This forbid closes the
// other half: a tool labelled egress (send, post, fetch, ...) may only talk
// to hosts you trust, whatever it sends. It is not active until you paste
// it into policy.cedar and run `rover policy apply`.
//
// How it works: for every argument a normaliser maps to a URL (the fetch
// server's "url" is built in; add your own in normalizers.yaml),
// context.norm.<arg>.host is the lowercased host, with userinfo rejected,
// so "https://api.github.com@evil.example" never passes as api.github.com.
// A call whose URL argument is not called "url", or which has no URL at all
// (an e-mail tool), is not covered: label and normalise it, or write a
// forbid per tool.
//
// To extend: add hosts to the list (exact names; "*.github.com" is not a
// pattern in Cedar, list each host). In policy.yaml the same allow-list is
// written per tool with host_in, which permits only the listed hosts
// (default deny does the rest); YAML has no "not in", so this
// forbid-everything-else form exists only in Cedar:
//
//   rules:
//     - id: fetch-allowed-hosts
//       allow: fetch.fetch
//       when: { host_in: [api.github.com, slack.com] }

// Forbids an egress tool from reaching any host not on the list, because a
// manipulated agent exfiltrates by sending data to an address the attacker
// chose (a URL, a markdown image, a webhook).
@id("egress-allowlist")
forbid (principal, action == Action::"call_tool", resource)
when {
  resource.labels.contains("egress") &&
  context.norm has url &&
  !["api.github.com", "slack.com"].contains(context.norm.url.host)
};
