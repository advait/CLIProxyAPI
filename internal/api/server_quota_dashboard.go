package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/usagerouting"
)

// serveQuotaDashboard serves the embedded usage-aware routing dashboard (fork
// addition). The page holds no data; it reads the v8 management API with the
// management key the viewer enters.
func (s *Server) serveQuotaDashboard(c *gin.Context) {
	cfg := s.getConfig()
	if cfg == nil || cfg.RemoteManagement.DisableControlPanel {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Data(http.StatusOK, "text/html; charset=utf-8", usagerouting.DashboardHTML)
}
