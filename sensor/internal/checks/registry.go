package checks

import (
	"time"

	"lava-sensor-exercise/sensor/internal/scan"
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

// Check titles name what was checked; the status says how it came out and the
// reason and evidence say why. A title never asserts a state, because the same
// title has to read correctly above pass, fail and unknown alike.

// All returns the explicit, ordered check roster.
//
// Order is cheap (pure sysfs and procfs reads) -> medium (a few bounded execs)
// -> expensive (bounded walks), so that a scan-deadline cut costs the fewest
// answers. The output is sorted by (category, check_id) regardless of this.
func All() []scan.Check {
	return []scan.Check{
		// --- cheap: sysfs and procfs reads only -----------------------------
		secureBootEnabled{meta{
			id: "SECURE_BOOT_ENABLED", category: CatBootChain,
			title: "UEFI Secure Boot state", impact: scan.SeverityHigh, budget: 5 * time.Second,
		}},
		uefiPlatformSetupMode{meta{
			id: "UEFI_PLATFORM_SETUP_MODE", category: CatBootChain,
			title: "UEFI platform key enrolment (Setup Mode)", impact: scan.SeverityCritical, budget: 5 * time.Second,
		}},
		kernelLockdownMode{meta{
			id: "KERNEL_LOCKDOWN_MODE", category: CatBootChain,
			title: "Kernel lockdown mode", impact: scan.SeverityMedium, budget: 5 * time.Second,
		}},
		unsignedOrOutOfTreeModules{meta{
			id: "UNSIGNED_OR_OUT_OF_TREE_MODULES", category: CatBootChain,
			title:  "Kernel taint from unsigned or out-of-tree modules, and module signature enforcement",
			impact: scan.SeverityMedium, budget: 10 * time.Second,
		}},
		tpmPresence{meta{
			id: "TPM_PRESENCE", category: CatBootChain,
			title: "TPM presence and version (inventory)", impact: scan.SeverityInfo,
			observational: true, budget: 5 * time.Second,
		}},
		bootArtifactReadability{meta{
			id: "BOOT_ARTIFACT_READABILITY", category: CatBootChain,
			title: "Readability of boot artifacts and the EFI system partition", impact: scan.SeverityLow, budget: 8 * time.Second,
		}},
		bootKernelDrift{meta{
			id: "BOOT_KERNEL_DRIFT", category: CatBootChain,
			title: "Running kernel versus the newest installed kernel", impact: scan.SeverityMedium, budget: 8 * time.Second,
		}},

		bmcInbandInterfacePresent{meta{
			id: "BMC_INBAND_INTERFACE_PRESENT", category: CatBMC,
			title: "Firmware declaration of an in-band management-controller interface", impact: scan.SeverityInfo,
			observational: true, budget: 5 * time.Second,
		}},
		bmcDeviceNodeAccess{meta{
			id: "BMC_DEVICE_NODE_ACCESS", category: CatBMC,
			title: "Who may open the in-band BMC device node", impact: scan.SeverityHigh, budget: 5 * time.Second,
		}},
		bmcRespondsInBand{meta{
			id: "BMC_RESPONDS_IN_BAND", category: CatBMC,
			title: "Whether the management controller answers the host in band", impact: scan.SeverityInfo,
			observational: true, budget: 6 * time.Second,
		}},
		bmcHostInterfaceExposure{meta{
			id: "BMC_HOST_INTERFACE_EXPOSURE", category: CatBMC,
			title:  "Latent BMC host interfaces (USB network gadget / Redfish host interface)",
			impact: scan.SeverityMedium, budget: 8 * time.Second,
		}},
		bmcClientToolingInventory{meta{
			id: "BMC_CLIENT_TOOLING_INVENTORY", category: CatBMC,
			title: "IPMI client tooling installed on the host (inventory)", impact: scan.SeverityInfo,
			observational: true, budget: 8 * time.Second,
		}},

		diskEncryptionAtRest{meta{
			id: "DISK_ENCRYPTION_AT_REST", category: CatStorage,
			title: "Block-level encryption at rest for the mounted filesystems", impact: scan.SeverityHigh, budget: 10 * time.Second,
		}},
		unusedAttachedBlockDevices{meta{
			id: "UNUSED_ATTACHED_BLOCK_DEVICES", category: CatStorage,
			title: "Whether every attached block device is accounted for", impact: scan.SeverityMedium, budget: 10 * time.Second,
		}},
		rootFilesystemRedundancy{meta{
			id: "ROOT_FILESYSTEM_REDUNDANCY", category: CatStorage,
			title: "Redundancy of the root filesystem against the loss of one device", impact: scan.SeverityLow, budget: 10 * time.Second,
		}},

		// --- medium: one or a few bounded subprocesses -----------------------
		sshRootLoginPolicy{meta{
			id: "SSH_ROOT_LOGIN_POLICY", category: CatRemoteAccess,
			title: "Root login policy of the running sshd (PermitRootLogin)", impact: scan.SeverityHigh, budget: 12 * time.Second,
		}},
		sshAuthMethodsPolicy{meta{
			id: "SSH_AUTH_METHODS_POLICY", category: CatRemoteAccess,
			title: "Authentication methods the running sshd accepts", impact: scan.SeverityHigh, budget: 12 * time.Second,
		}},
		sshPolicyInForce{meta{
			id: "SSH_POLICY_IN_FORCE", category: CatRemoteAccess,
			title:  "Whether the sshd configuration on disk is the one the running daemon loaded",
			impact: scan.SeverityMedium, budget: 12 * time.Second,
		}},
		remoteListeningSurface{meta{
			id: "REMOTE_LISTENING_SURFACE", category: CatRemoteAccess,
			title: "Services listening on non-loopback addresses", impact: scan.SeverityMedium, budget: 15 * time.Second,
		}},
		loginAndEscalationSurface{meta{
			id: "LOGIN_AND_ESCALATION_SURFACE", category: CatRemoteAccess,
			title: "Who can log in to this machine and who can escalate to root", impact: scan.SeverityMedium, budget: 12 * time.Second,
		}},
		hostFirewallState{meta{
			id: "HOST_FIREWALL_STATE", category: CatRemoteAccess,
			title: "Host packet-filter state and whether its policy is verifiable", impact: scan.SeverityMedium, budget: 15 * time.Second,
		}},
		mediaHealthVisibility{meta{
			id: "MEDIA_HEALTH_VISIBILITY", category: CatStorage,
			title: "Observability of drive health telemetry, and what it shows", impact: scan.SeverityMedium, budget: 15 * time.Second,
		}},

		// --- expensive: bounded filesystem walks -----------------------------
		systemSecretStoreProtection{meta{
			id: "SYSTEM_SECRET_STORE_PROTECTION", category: CatSecrets,
			title: "Permissions of the operating system's own secret stores", impact: scan.SeverityHigh, budget: 10 * time.Second,
		}},
		provisioningDataProtection{meta{
			id: "PROVISIONING_DATA_PROTECTION", category: CatSecrets,
			title: "Readability of provisioning and instance metadata on disk", impact: scan.SeverityMedium, budget: 15 * time.Second,
		}},
		credentialFileExposure{meta{
			id: "CREDENTIAL_FILE_EXPOSURE", category: CatSecrets,
			title:  "Application credential files against the permission rules their own software documents",
			impact: scan.SeverityHigh, budget: 20 * time.Second,
		}},
		privateKeyMaterialExposure{meta{
			id: "PRIVATE_KEY_MATERIAL_EXPOSURE", category: CatSecrets,
			title: "Readability of private key material on disk", impact: scan.SeverityHigh, budget: 25 * time.Second,
		}},
	}
}
