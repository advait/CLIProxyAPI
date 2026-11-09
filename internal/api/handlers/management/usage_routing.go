package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// GetUsageRouting reports cached subscription usage, scores, and exhaustion per
// credential for the usage-aware routing strategy (fork addition).
func (h *Handler) GetUsageRouting(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled":     coreauth.UsageRoutingEnabled(),
		"credentials": coreauth.UsageRoutingReport(),
	})
}
