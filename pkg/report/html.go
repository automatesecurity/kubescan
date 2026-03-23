package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"kubescan/pkg/attackpath"
	"kubescan/pkg/policy"
)

type htmlMetric struct {
	Label string
	Value string
	Tone  string
}

type htmlSummarySection struct {
	Title   string
	Entries []SummaryEntry
}

type htmlFindingView struct {
	ID               string
	RuleID           string
	Title            string
	Severity         policy.Severity
	SeverityLabel    string
	Category         string
	Resource         string
	Message          string
	Remediation      string
	RuleVersion      string
	OriginalSeverity string
	Timestamp        string
	EvidenceJSON     string
}

type htmlFindingGroup struct {
	Resource string
	Count    int
	Findings []htmlFindingView
}

type htmlAttackPathView struct {
	ID              string
	Title           string
	Severity        policy.Severity
	SeverityLabel   string
	Entry           string
	Target          string
	Path            string
	Summary         string
	Remediation     string
	SupportingRules string
	Steps           []attackpath.Step
}

type htmlComplianceControlView struct {
	ID              string
	Status          string
	FailingFindings int
}

type htmlComplianceView struct {
	Profile        string
	Status         string
	PassedControls int
	FailedControls int
	Controls       []htmlComplianceControlView
}

type htmlReportView struct {
	Title          string
	GeneratedAt    string
	GeneratedYear  int
	APIVersion     string
	Kind           string
	Schema         string
	SchemaVersion  string
	Metrics        []htmlMetric
	Summary        []htmlSummarySection
	Compliance     *htmlComplianceView
	AttackPaths    []htmlAttackPathView
	FindingGroups  []htmlFindingGroup
	HasFindings    bool
	HasAttackPaths bool
	RawJSON        string
}

func WriteHTML(w io.Writer, result ScanResult) error {
	view, err := buildHTMLReportView(result.normalized())
	if err != nil {
		return err
	}
	return htmlReportTemplate.Execute(w, view)
}

func buildHTMLReportView(result ScanResult) (htmlReportView, error) {
	rawJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return htmlReportView{}, fmt.Errorf("marshal raw JSON: %w", err)
	}

	view := htmlReportView{
		Title:          "Kubescan HTML Report",
		GeneratedAt:    result.GeneratedAt.Format(time.RFC3339),
		GeneratedYear:  2026,
		APIVersion:     result.APIVersion,
		Kind:           result.Kind,
		Schema:         result.Schema,
		SchemaVersion:  result.SchemaVersion,
		HasFindings:    len(result.Findings) > 0,
		HasAttackPaths: len(result.AttackPaths) > 0,
		RawJSON:        string(rawJSON),
		Metrics: []htmlMetric{
			{Label: "Findings", Value: fmt.Sprintf("%d", result.Summary.TotalFindings), Tone: "neutral"},
			{Label: "Severity Mix", Value: severityMix(result.Summary.TotalBySeverity), Tone: "neutral"},
		},
		Summary: []htmlSummarySection{
			{Title: "Top Rules", Entries: limitSummaryEntries(result.Summary.ByRule, 10)},
			{Title: "Top Namespaces", Entries: limitSummaryEntries(result.Summary.ByNamespace, 10)},
			{Title: "Categories", Entries: limitSummaryEntries(result.Summary.ByCategory, 10)},
		},
	}
	if result.Summary.AttackPaths.TotalPaths > 0 {
		view.Metrics = append(view.Metrics,
			htmlMetric{Label: "Attack Paths", Value: fmt.Sprintf("%d", result.Summary.AttackPaths.TotalPaths), Tone: "critical"},
			htmlMetric{Label: "Attack Path Mix", Value: severityMix(result.Summary.AttackPaths.TotalBySeverity), Tone: "critical"},
		)
		view.Summary = append(view.Summary, htmlSummarySection{
			Title:   "Attack Path IDs",
			Entries: limitSummaryEntries(result.Summary.AttackPaths.ByID, 10),
		})
	}
	if result.Compliance != nil {
		status := complianceStatus(result.Compliance)
		view.Metrics = append(view.Metrics, htmlMetric{
			Label: "Compliance",
			Value: strings.ToUpper(status),
			Tone:  status,
		})
		controls := make([]htmlComplianceControlView, 0, len(result.Compliance.Controls))
		for _, control := range result.Compliance.Controls {
			controls = append(controls, htmlComplianceControlView{
				ID:              control.ID,
				Status:          string(control.Status),
				FailingFindings: control.FailingFindings,
			})
		}
		view.Compliance = &htmlComplianceView{
			Profile:        result.Compliance.Profile,
			Status:         status,
			PassedControls: result.Compliance.PassedControls,
			FailedControls: result.Compliance.FailedControls,
			Controls:       controls,
		}
	}

	findings := append([]policy.Finding(nil), result.Findings...)
	sortFindings(findings)
	view.FindingGroups = buildHTMLFindingGroups(findings)
	view.AttackPaths = buildHTMLAttackPaths(result.AttackPaths)

	return view, nil
}

func limitSummaryEntries(entries []SummaryEntry, limit int) []SummaryEntry {
	if len(entries) <= limit {
		return entries
	}
	return entries[:limit]
}

func buildHTMLFindingGroups(findings []policy.Finding) []htmlFindingGroup {
	if len(findings) == 0 {
		return nil
	}
	groups := groupFindingsByResource(findings)
	result := make([]htmlFindingGroup, 0, len(groups))
	for _, group := range groups {
		items := make([]htmlFindingView, 0, len(group.Findings))
		for _, finding := range group.Findings {
			evidenceJSON := ""
			if len(finding.Evidence) > 0 {
				if content, err := json.MarshalIndent(finding.Evidence, "", "  "); err == nil {
					evidenceJSON = string(content)
				}
			}
			items = append(items, htmlFindingView{
				ID:               finding.ID,
				RuleID:           finding.RuleID,
				Title:            finding.Title,
				Severity:         finding.Severity,
				SeverityLabel:    strings.ToUpper(severityLabel(finding.Severity)),
				Category:         categoryLabel(finding.Category),
				Resource:         fullyQualifiedResource(finding.Resource),
				Message:          finding.Message,
				Remediation:      finding.Remediation,
				RuleVersion:      finding.RuleVersion,
				OriginalSeverity: string(finding.OriginalSeverity),
				Timestamp:        finding.Timestamp.UTC().Format(time.RFC3339),
				EvidenceJSON:     evidenceJSON,
			})
		}
		result = append(result, htmlFindingGroup{
			Resource: group.Resource,
			Count:    len(items),
			Findings: items,
		})
	}
	return result
}

func buildHTMLAttackPaths(paths []attackpath.Result) []htmlAttackPathView {
	if len(paths) == 0 {
		return nil
	}
	sorted := append([]attackpath.Result(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool {
		left := severityWeight(sorted[i].Severity)
		right := severityWeight(sorted[j].Severity)
		if left != right {
			return left > right
		}
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		return fullyQualifiedResource(sorted[i].Entry) < fullyQualifiedResource(sorted[j].Entry)
	})
	result := make([]htmlAttackPathView, 0, len(sorted))
	for _, path := range sorted {
		result = append(result, htmlAttackPathView{
			ID:              path.ID,
			Title:           path.Title,
			Severity:        path.Severity,
			SeverityLabel:   strings.ToUpper(severityLabel(path.Severity)),
			Entry:           fullyQualifiedResource(path.Entry),
			Target:          path.Target,
			Path:            path.Path,
			Summary:         path.Summary,
			Remediation:     path.Remediation,
			SupportingRules: strings.Join(path.SupportingRules, ", "),
			Steps:           path.Steps,
		})
	}
	return result
}

var htmlReportTemplate = template.Must(template.New("report-html").Funcs(template.FuncMap{
	"severityClass": severityClass,
	"toneClass":     toneClass,
	"upper":         strings.ToUpper,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      --bg: #f4f1e8;
      --panel: #fffdf8;
      --panel-2: #f7f2e9;
      --ink: #17212b;
      --muted: #576575;
      --line: #d8cdb7;
      --crit: #8f1d1d;
      --high: #c44f19;
      --med: #9d7a12;
      --low: #2d6a4f;
      --accent: #0f4c5c;
      --accent-2: #c97b63;
      --shadow: 0 12px 30px rgba(23,33,43,0.08);
      --radius: 16px;
      --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      --sans: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      background:
        radial-gradient(circle at top right, rgba(201,123,99,0.18), transparent 28rem),
        linear-gradient(180deg, #f7f3ea 0%, var(--bg) 100%);
      color: var(--ink);
      font-family: var(--sans);
      line-height: 1.5;
    }
    .wrap {
      max-width: 1360px;
      margin: 0 auto;
      padding: 32px 24px 80px;
    }
    .hero, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .hero {
      padding: 28px;
      position: relative;
      overflow: hidden;
    }
    .hero::after {
      content: "";
      position: absolute;
      inset: auto -40px -40px auto;
      width: 220px;
      height: 220px;
      background: radial-gradient(circle, rgba(15,76,92,0.14), transparent 70%);
      pointer-events: none;
    }
    .hero h1 {
      margin: 0 0 6px;
      font-size: 34px;
      line-height: 1.1;
    }
    .subtle { color: var(--muted); }
    .subtle a { color: inherit; }
    .meta-grid, .metrics, .summary-grid, .findings-grid, .attack-grid {
      display: grid;
      gap: 16px;
    }
    .meta-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 18px; }
    .metrics { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 24px; }
    .summary-grid { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
    .attack-grid, .findings-grid { grid-template-columns: 1fr; }
    .metric, .summary-card, .attack-card, .finding-group, .panel-inner {
      background: var(--panel-2);
      border: 1px solid var(--line);
      border-radius: 14px;
    }
    .metric { padding: 16px; }
    .metric .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .metric .value { margin-top: 6px; font-size: 24px; font-weight: 700; }
    .metric.tone-critical .value, .severity-critical { color: var(--crit); }
    .metric.tone-high .value, .severity-high { color: var(--high); }
    .metric.tone-medium .value, .severity-medium { color: var(--med); }
    .metric.tone-low .value, .severity-low { color: var(--low); }
    .metric.tone-failing .value { color: var(--high); }
    .metric.tone-passing .value { color: var(--low); }
    .section { margin-top: 24px; }
    .section > .panel { padding: 22px; }
    .section h2 { margin: 0 0 14px; font-size: 24px; }
    .section h3 { margin: 0 0 10px; font-size: 16px; }
    .kv { padding: 14px; }
    .kv dt {
      font-size: 12px;
      text-transform: uppercase;
      color: var(--muted);
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }
    .kv dd { margin: 0; font-family: var(--mono); font-size: 14px; }
    .summary-card { padding: 18px; }
    .summary-card table, .compliance-table, .finding-table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px 0; vertical-align: top; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); border-bottom: 1px solid var(--line); }
    td { border-bottom: 1px solid rgba(216,205,183,0.7); }
    tr:last-child td { border-bottom: none; }
    .toolbar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .toolbar label {
      display: block;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .toolbar input, .toolbar select {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      color: var(--ink);
      font: inherit;
    }
    .finding-group { overflow: hidden; }
    .finding-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(15,76,92,0.08), transparent);
    }
    .finding-cards { padding: 16px; display: grid; gap: 14px; }
    .finding-card, .attack-card {
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
    }
    .finding-meta, .attack-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 10px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid currentColor;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .mono { font-family: var(--mono); }
    .details {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
      display: grid;
      gap: 10px;
    }
    details summary {
      cursor: pointer;
      font-weight: 700;
    }
    pre {
      margin: 0;
      padding: 14px;
      overflow: auto;
      border-radius: 12px;
      background: #191f26;
      color: #e5edf5;
      font: 13px/1.5 var(--mono);
    }
    .empty {
      padding: 18px;
      border: 1px dashed var(--line);
      border-radius: 12px;
      color: var(--muted);
      background: rgba(255,255,255,0.55);
    }
    .attack-steps { margin: 10px 0 0; padding-left: 18px; }
    .footer-note { margin-top: 20px; color: var(--muted); font-size: 13px; }
    @media (max-width: 720px) {
      .wrap { padding: 18px 14px 48px; }
      .hero { padding: 20px; }
      .hero h1 { font-size: 28px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>{{.Title}}</h1>
      <div class="subtle">Kubescan (c) {{.GeneratedYear}} Daniel Wood <a href="https://www.github.com/automatesecurity/kubescan">https://www.github.com/automatesecurity/kubescan</a></div>
      <div class="subtle">Generated {{.GeneratedAt}} · {{.APIVersion}} · {{.Schema}} {{.SchemaVersion}}</div>

      <div class="meta-grid">
        <dl class="kv"><dt>apiVersion</dt><dd>{{.APIVersion}}</dd></dl>
        <dl class="kv"><dt>kind</dt><dd>{{.Kind}}</dd></dl>
        <dl class="kv"><dt>schema</dt><dd>{{.Schema}}</dd></dl>
        <dl class="kv"><dt>schemaVersion</dt><dd>{{.SchemaVersion}}</dd></dl>
      </div>

      <div class="metrics">
        {{range .Metrics}}
        <div class="metric {{toneClass .Tone}}">
          <div class="label">{{.Label}}</div>
          <div class="value">{{.Value}}</div>
        </div>
        {{end}}
      </div>
    </section>

    <section class="section">
      <div class="panel">
        <h2>Summary</h2>
        <div class="summary-grid">
          {{range .Summary}}
          <div class="summary-card">
            <h3>{{.Title}}</h3>
            {{if .Entries}}
            <table>
              <thead><tr><th>Name</th><th>Count</th></tr></thead>
              <tbody>
                {{range .Entries}}
                <tr><td class="mono">{{.Name}}</td><td>{{.Count}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{else}}
            <div class="empty">No entries.</div>
            {{end}}
          </div>
          {{end}}
        </div>
      </div>
    </section>

    {{if .Compliance}}
    <section class="section">
      <div class="panel">
        <h2>Compliance</h2>
        <div class="metrics">
          <div class="metric tone-neutral"><div class="label">Profile</div><div class="value">{{.Compliance.Profile}}</div></div>
          <div class="metric {{toneClass .Compliance.Status}}"><div class="label">Status</div><div class="value">{{upper .Compliance.Status}}</div></div>
          <div class="metric tone-low"><div class="label">Passed</div><div class="value">{{.Compliance.PassedControls}}</div></div>
          <div class="metric tone-high"><div class="label">Failed</div><div class="value">{{.Compliance.FailedControls}}</div></div>
        </div>
        {{if .Compliance.Controls}}
        <table class="compliance-table">
          <thead><tr><th>Control</th><th>Status</th><th>Failing Findings</th></tr></thead>
          <tbody>
            {{range .Compliance.Controls}}
            <tr>
              <td class="mono">{{.ID}}</td>
              <td class="{{severityClass .Status}}">{{upper .Status}}</td>
              <td>{{.FailingFindings}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
        {{end}}
      </div>
    </section>
    {{end}}

    <section class="section">
      <div class="panel">
        <h2>Attack Paths</h2>
        {{if .HasAttackPaths}}
        <div class="toolbar">
          <div>
            <label for="attack-search">Search</label>
            <input id="attack-search" type="search" placeholder="Find entry, target, rule, or path">
          </div>
          <div>
            <label for="attack-severity">Severity</label>
            <select id="attack-severity">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
        <div class="attack-grid" id="attack-list">
          {{range .AttackPaths}}
          <article class="attack-card attack-row" data-search="{{.ID}} {{.Title}} {{.Entry}} {{.Target}} {{.Path}} {{.SupportingRules}}" data-severity="{{.Severity}}">
            <div class="attack-meta">
              <span class="pill {{severityClass .Severity}}">{{.SeverityLabel}}</span>
              <span class="pill mono">{{.ID}}</span>
              <span class="pill mono">{{.Entry}}</span>
            </div>
            <h3>{{.Title}}</h3>
            <div class="subtle">{{.Summary}}</div>
            <div class="details">
              <div><strong>Target:</strong> {{.Target}}</div>
              <div><strong>Path:</strong> <span class="mono">{{.Path}}</span></div>
              {{if .SupportingRules}}<div><strong>Supporting rules:</strong> <span class="mono">{{.SupportingRules}}</span></div>{{end}}
              <div><strong>Remediation:</strong> {{.Remediation}}</div>
              {{if .Steps}}
              <div>
                <strong>Steps:</strong>
                <ol class="attack-steps">
                  {{range .Steps}}
                  <li>{{.Label}}{{if .Relationship}} <span class="subtle">via {{.Relationship}}</span>{{end}}</li>
                  {{end}}
                </ol>
              </div>
              {{end}}
            </div>
          </article>
          {{end}}
        </div>
        {{else}}
        <div class="empty">No attack paths were emitted for this result.</div>
        {{end}}
      </div>
    </section>

    <section class="section">
      <div class="panel">
        <h2>Findings</h2>
        {{if .HasFindings}}
        <div class="toolbar">
          <div>
            <label for="finding-search">Search</label>
            <input id="finding-search" type="search" placeholder="Find rule, resource, title, message, or evidence">
          </div>
          <div>
            <label for="finding-severity">Severity</label>
            <select id="finding-severity">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label for="finding-category">Category</label>
            <select id="finding-category">
              <option value="">All categories</option>
              <option value="vuln">Vuln</option>
              <option value="misconfig">Misconfig</option>
              <option value="exposure">Exposure</option>
              <option value="identity">Identity</option>
              <option value="resilience">Resilience</option>
              <option value="supply-chain">Supply Chain</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
        </div>
        <div class="findings-grid" id="finding-list">
          {{range .FindingGroups}}
          <section class="finding-group finding-group-row">
            <div class="finding-head">
              <div>
                <strong class="mono">{{.Resource}}</strong>
                <div class="subtle">{{.Count}} finding(s)</div>
              </div>
            </div>
            <div class="finding-cards">
              {{range .Findings}}
              <article class="finding-card finding-row" data-search="{{.RuleID}} {{.Title}} {{.Category}} {{.Resource}} {{.Message}} {{.EvidenceJSON}}" data-severity="{{.Severity}}" data-category="{{.Category}}">
                <div class="finding-meta">
                  <span class="pill {{severityClass .Severity}}">{{.SeverityLabel}}</span>
                  <span class="pill mono">{{.RuleID}}</span>
                  <span class="pill">{{upper .Category}}</span>
                  {{if .OriginalSeverity}}<span class="pill">was {{upper .OriginalSeverity}}</span>{{end}}
                </div>
                <h3>{{if .Title}}{{.Title}}{{else}}{{.RuleID}}{{end}}</h3>
                <div>{{.Message}}</div>
                <div class="details">
                  {{if .Remediation}}<div><strong>Remediation:</strong> {{.Remediation}}</div>{{end}}
                  {{if .RuleVersion}}<div><strong>Rule version:</strong> <span class="mono">{{.RuleVersion}}</span></div>{{end}}
                  {{if .Timestamp}}<div><strong>Timestamp:</strong> <span class="mono">{{.Timestamp}}</span></div>{{end}}
                  {{if .EvidenceJSON}}
                  <details>
                    <summary>Evidence</summary>
                    <pre>{{.EvidenceJSON}}</pre>
                  </details>
                  {{end}}
                </div>
              </article>
              {{end}}
            </div>
          </section>
          {{end}}
        </div>
        {{else}}
        <div class="empty">No findings were emitted for this result.</div>
        {{end}}
      </div>
    </section>

    <section class="section">
      <div class="panel">
        <h2>Raw Result</h2>
        <div class="footer-note">This embedded JSON uses the stable scan-result schema and is included so the HTML remains useful for future integrations and offline review.</div>
        <pre>{{.RawJSON}}</pre>
      </div>
    </section>
  </div>

  <script>
    (function () {
      function bindFilter(config) {
        const search = document.getElementById(config.searchId);
        const severity = document.getElementById(config.severityId);
        const category = config.categoryId ? document.getElementById(config.categoryId) : null;
        const rows = Array.from(document.querySelectorAll(config.rowSelector));
        if (!search || !severity || rows.length === 0) return;
        function apply() {
          const searchValue = search.value.trim().toLowerCase();
          const severityValue = severity.value;
          const categoryValue = category ? category.value : "";
          rows.forEach((row) => {
            const matchesSearch = !searchValue || (row.dataset.search || "").toLowerCase().includes(searchValue);
            const matchesSeverity = !severityValue || row.dataset.severity === severityValue;
            const matchesCategory = !categoryValue || row.dataset.category === categoryValue;
            row.style.display = matchesSearch && matchesSeverity && matchesCategory ? "" : "none";
          });
          if (config.groupSelector) {
            document.querySelectorAll(config.groupSelector).forEach((group) => {
              const children = Array.from(group.querySelectorAll(config.rowSelector));
              const visibleChildren = children.filter((child) => child.style.display !== "none").length;
              group.style.display = visibleChildren > 0 ? "" : "none";
            });
          }
        }
        [search, severity, category].filter(Boolean).forEach((el) => el.addEventListener("input", apply));
        [search, severity, category].filter(Boolean).forEach((el) => el.addEventListener("change", apply));
        apply();
      }
      bindFilter({
        searchId: "finding-search",
        severityId: "finding-severity",
        categoryId: "finding-category",
        rowSelector: ".finding-row",
        groupSelector: ".finding-group-row"
      });
      bindFilter({
        searchId: "attack-search",
        severityId: "attack-severity",
        rowSelector: ".attack-row"
      });
    }());
  </script>
</body>
</html>`))

func severityClass(value any) string {
	switch typed := value.(type) {
	case policy.Severity:
		return "severity-" + string(typed)
	case string:
		switch strings.ToLower(typed) {
		case "critical", "high", "medium", "low", "failing", "passing", "fail", "pass":
			if typed == "fail" {
				return "severity-high"
			}
			if typed == "pass" {
				return "severity-low"
			}
			if typed == "failing" {
				return "severity-high"
			}
			if typed == "passing" {
				return "severity-low"
			}
			return "severity-" + strings.ToLower(typed)
		}
	}
	return ""
}

func toneClass(value string) string {
	if strings.TrimSpace(value) == "" {
		return "tone-neutral"
	}
	return "tone-" + strings.ToLower(value)
}
