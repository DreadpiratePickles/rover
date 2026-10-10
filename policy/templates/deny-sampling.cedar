// Template: no server may use your model or ask you questions directly.

// Forbids server->client sampling, because a server could use your model and
// your context with prompts you never see.
@id("deny-sampling")
forbid (principal, action == Action::"server_sampling", resource);

// Forbids server->client elicitation, because a server could ask you for
// secrets in a dialog that looks like it comes from your client.
@id("deny-elicitation")
forbid (principal, action == Action::"server_elicitation", resource);
