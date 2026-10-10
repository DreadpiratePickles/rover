// Template: break the "lethal trifecta" (private data + untrusted content +
// a way out). Both forbids are already active in the starter policy.cedar
// that `rover policy init` writes (same ids, so do not paste this file into
// it). Labels come from the built-in list, config.yaml, and the conservative
// default ({reads_untrusted, egress}); see `rover policy labels`.

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
