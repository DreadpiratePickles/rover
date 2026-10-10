// Template: the official filesystem server may only work inside "projects".

// Permits listing the filesystem server's tools, because the agent needs the
// list to know what it may call.
@id("fs-list-tools")
permit (principal, action == Action::"list_tools", resource == Server::"filesystem");

// Permits filesystem tools whose "path" argument resolves inside the root
// named "projects", because norm.path has "..", symlinks and look-alike
// separators already resolved. Tools without a path argument stay denied:
// `has` is false for them. (Every norm attribute is optional, so strict
// validation requires the `has` guard before the attribute is read.)
@id("fs-path-under-projects")
permit (principal, action == Action::"call_tool", resource in Server::"filesystem")
when { context.norm has path.under_projects && context.norm.path.under_projects };

// Permits move_file only when both ends are inside "projects", because a move
// out of the root is as dangerous as a write outside it.
@id("fs-move-within-projects")
permit (principal, action == Action::"call_tool", resource == Tool::"filesystem/move_file")
when {
  context.norm has source.under_projects && context.norm.source.under_projects &&
  context.norm has destination.under_projects && context.norm.destination.under_projects
};

// Permits read_multiple_files only when every listed path is inside
// "projects", because one stray path is enough to leak a secret.
@id("fs-multi-read-projects")
permit (principal, action == Action::"call_tool", resource == Tool::"filesystem/read_multiple_files")
when { context.norm has paths.all_under_projects && context.norm.paths.all_under_projects };
