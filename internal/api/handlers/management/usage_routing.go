package management

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/usagerouting"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// GetUsageRouting reports cached subscription usage, scores, and exhaustion per
// credential for the usage-aware routing strategy (fork addition).
func (h *Handler) GetUsageRouting(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled":     coreauth.UsageRoutingEnabled(),
		"now":         time.Now().UTC(),
		"credentials": coreauth.UsageRoutingReport(),
	})
}

// GetUsageRoutingHistory returns recorded usage samples for the last ?hours=
// (default 168, max 720).
func (h *Handler) GetUsageRoutingHistory(c *gin.Context) {
	hours := 168
	if raw := c.Query("hours"); raw != "" {
		parsed, errParse := strconv.Atoi(raw)
		if errParse != nil || parsed <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hours must be a positive integer"})
			return
		}
		hours = min(parsed, int(coreauth.UsageHistoryRetention/time.Hour))
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	c.JSON(http.StatusOK, gin.H{"since": since.UTC(), "samples": coreauth.UsageHistory(since)})
}

// PostUsageRoutingRefresh polls every credential's usage immediately.
func (h *Handler) PostUsageRoutingRefresh(c *gin.Context) {
	if errRefresh := usagerouting.Refresh(c.Request.Context()); errRefresh != nil {
		c.JSON(http.StatusConflict, gin.H{"error": errRefresh.Error()})
		return
	}
	h.GetUsageRouting(c)
}
