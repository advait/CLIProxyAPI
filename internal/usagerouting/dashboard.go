package usagerouting

import _ "embed"

// DashboardHTML is the quota dashboard served at /quota.html.
//
//go:embed dashboard.html
var DashboardHTML []byte
