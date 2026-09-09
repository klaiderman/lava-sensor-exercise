package checks

import (
	"time"

	"lava.sh/sensor/internal/scan"
)

// meta carries a check's registry metadata. Each check is its own named Go type
// embedding it, so the roster stays explicit and greppable: there is no
// data-driven table and no init()-time self-registration (LD-9).
type meta struct {
	id            string
	category      string
	title         string
	impact        string
	observational bool
	budget        time.Duration
}

func (m meta) ID() string          { return m.id }
func (m meta) Category() string    { return m.category }
func (m meta) Title() string       { return m.title }
func (m meta) Impact() string      { return m.impact }
func (m meta) Observational() bool { return m.observational }
func (m meta) Budget() time.Duration {
	if m.budget == 0 {
		return scan.DefaultCheckBudget
	}
	return m.budget
}

// Categories used by the roster. The two custom ones are STORAGE_POSTURE and
// BOOT_CHAIN; their rationale is in reports/IMPLEMENTATION_NOTES.md.
const (
	CatRemoteAccess = "REMOTE_ACCESS"
	CatSecrets      = "SECRETS_ON_DISK"
	CatBMC          = "BMC_INBAND_ACCESS"
	CatStorage      = "STORAGE_POSTURE"
	CatBootChain    = "BOOT_CHAIN"
)

// All returns the explicit, ordered check roster.
//
// Order is cheap -> medium -> expensive, so that a scan-deadline cut costs the
// fewest answers; the output is sorted by (category, check_id) regardless.
func All() []scan.Check {
	return []scan.Check{
		sshRootLoginPolicy{meta{
			id:       "SSH_ROOT_LOGIN_POLICY",
			category: CatRemoteAccess,
			title:    "Root login over SSH is not permitted by the running sshd policy",
			impact:   scan.SeverityHigh,
			budget:   10 * time.Second,
		}},
	}
}
