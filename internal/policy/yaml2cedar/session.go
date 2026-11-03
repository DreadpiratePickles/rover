package yaml2cedar

import (
	"strconv"

	"gopkg.in/yaml.v3"
)

// session: {touched_private: bool, saw_untrusted: bool, servers_touched:
// [server, ...]}. servers_touched means every listed server (AND).
func (c compiler) session(n *yaml.Node) ([]cond, error) {
	fields, err := c.mapping(n, "when.session", "touched_private", "saw_untrusted", "servers_touched")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, c.errAt(n, "when.session: needs touched_private, saw_untrusted and/or servers_touched")
	}
	out := make([]cond, 0, len(fields))
	for _, f := range fields {
		if f.key.Value == "servers_touched" {
			cs, err := c.serversTouched(f.val)
			if err != nil {
				return nil, err
			}
			out = append(out, cs...)
			continue
		}
		b, err := c.boolean(f.val, "session."+f.key.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, cond{cedar: "context.session." + f.key.Value + " == " + strconv.FormatBool(b)})
	}
	return out, nil
}

// serversTouched: [server, ...] -> one contains() per server. Names are
// restricted to serverRE, so they never need escaping in Cedar.
func (c compiler) serversTouched(n *yaml.Node) ([]cond, error) {
	items, err := c.sequence(n, "session.servers_touched")
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, c.errAt(n, "session.servers_touched: needs at least one server")
	}
	out := make([]cond, 0, len(items))
	for _, it := range items {
		name, err := c.str(it, "a server name")
		if err != nil {
			return nil, err
		}
		if !serverRE.MatchString(name) {
			return nil, c.errAt(it, "%q is not a server name (letters, digits, _ and -)", name)
		}
		out = append(out, cond{cedar: `context.session.servers_touched.contains("` + name + `")`})
	}
	return out, nil
}
