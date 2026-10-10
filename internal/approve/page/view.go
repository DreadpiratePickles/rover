package page

import (
	"html/template"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

// The page looks like a cwm menu (plan §4.7): white background, black bold
// 14px sans-serif, one box with a 1px black border, the prompt line
// `approval»<id>«` first, then one entry per line with no padding, the box
// as wide as its widest line. The state line is cwm's urgent colour
// #FC8814 while the approval is pending. No script, no form, no input, no
// link, no image, no external resource: html/template escapes every value,
// and the Content-Security-Policy header forbids anything else anyway.
var tmpl = template.Must(template.New("approval").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>approval»{{.ID}}«</title>
<style>
body { background:#fff; color:#000; font: bold 14px sans-serif; margin:0 }
.menu { display:inline-block; border:1px solid #000 }
.menu div { white-space:pre; margin:0; padding:0 }
.urgent { color:#FC8814 }
</style></head>
<body><div class="menu">
<div>approval»{{.ID}}«</div>
{{range .Rows}}<div{{if .Urgent}} class="urgent"{{end}}>{{.Text}}</div>
{{end}}</div></body></html>
`))

type row struct {
	Text   string
	Urgent bool
}

type view struct {
	ID   string
	Rows []row
}

// maxArgs caps the arguments shown.
const maxArgs = 4 << 10

func (s *Server) view(rec approve.Record, l link) view {
	stateText := strings.ReplaceAll(rec.State, "_", " ")
	pending := rec.State == approve.StatePending
	if pending && !rec.Deadline.IsZero() && s.now().After(rec.Deadline) {
		stateText = "pending, past its deadline (roverd denies it)"
	}
	rows := []row{
		{Text: "state " + stateText, Urgent: pending},
		{Text: "id " + approve.ShortID(rec.ID) + " (the system dialog shows the same)"},
		{Text: "client " + clean(rec.Client, "unknown")},
		{Text: "server " + clean(rec.Server, "-")},
		{Text: "tool " + clean(rec.Tool, "-")},
	}
	if rec.Summary != "" {
		rows = append(rows, row{Text: "summary " + approve.Clean(rec.Summary)})
	}
	rows = append(rows,
		row{Text: "rules " + clean(strings.Join(rec.RuleIDs, ", "), "-")},
		row{Text: "session " + clean(rec.Session, "-")},
		row{Text: "asked " + stamp(rec.Created)},
		row{Text: "deadline " + stamp(rec.Deadline)},
	)
	if !pending {
		rows = append(rows, row{Text: "decided " + stamp(rec.DecidedAt) + " by " + clean(rec.Method, "-")})
	}
	switch {
	case !l.shown:
		rows = append(rows, row{Text: "args hidden: approvals.show_args is false (rover does not redact secrets until M10)"})
	case len(l.args) == 0:
		rows = append(rows, row{Text: "args none"})
	default:
		a := string(l.args)
		if len(a) > maxArgs {
			a = a[:maxArgs] + "..."
		}
		rows = append(rows, row{Text: "args (not redacted) " + strings.ToValidUTF8(a, "?")})
	}
	rows = append(rows, row{Text: "this page cannot approve. answer the system authentication dialog."})
	return view{ID: rec.ID, Rows: rows}
}

func clean(s, empty string) string {
	if s == "" {
		return empty
	}
	return approve.Clean(s)
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
