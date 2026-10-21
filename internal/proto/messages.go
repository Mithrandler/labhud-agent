package proto

// The messages of docs/agent-protocol.md. The unsigned ones come first.

type Welcome struct {
	Type    string `json:"type"` // "welcome"
	V       int    `json:"v"`
	Session string `json:"session"`
}

type Pair struct {
	Type       string `json:"type"` // "pair"
	CodeID     string `json:"code_id"`
	AgentNonce string `json:"agent_nonce"`
	Name       string `json:"name"`
}

type Challenge struct {
	Type        string `json:"type"` // "challenge"
	AgentID     string `json:"agent_id"`
	ServerNonce string `json:"server_nonce"`
	TLSFP       string `json:"tls_fp"`
	Proof       string `json:"proof"`
}

// Unsigned is the first look at an unsigned message: its type, and the error of an "error".
type Unsigned struct {
	Type  string `json:"type"`
	Error string `json:"error"`
}

// --- signed, agent to labhud ---

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

type Hello struct {
	Type    string   `json:"type"` // "hello"
	Version string   `json:"version"`
	Name    string   `json:"name,omitempty"`
	Host    Host     `json:"host"`
	Caps    []string `json:"caps"`
	// Install: "service" (systemd, it can replace its own binary) or "container" (its image does)
	Install string `json:"install,omitempty"`
	// Features: what this agent understands beyond v1's first messages ("registry-auth": a
	// command's sealed Auth), so that labhud sends nothing an older agent would drop
	Features []string `json:"features,omitempty"`
}

// State: every part is optional; nil means "not on this host".
type State struct {
	Type       string                    `json:"type"` // "state"
	Sensors    map[string]any            `json:"sensors,omitempty"`
	Guests     map[string]map[string]any `json:"guests,omitempty"`
	Containers map[string]map[string]any `json:"containers,omitempty"`
	Units      map[string]map[string]any `json:"units,omitempty"`
	Servers    map[string]map[string]any `json:"servers,omitempty"`
	Neighbours map[string]map[string]any `json:"neighbours,omitempty"`
	// Stacks: the compose projects labhud keeps on this host (the stacks capability)
	Stacks map[string]map[string]any `json:"stacks,omitempty"`
	Node   string                    `json:"node,omitempty"` // the Proxmox node, with guests
	// FailedUnits: every systemd unit in the failed state, of any type, ticked or not (null
	// without systemd, [] when none failed)
	FailedUnits []string `json:"failed_units"`
}

type Result struct {
	Type  string `json:"type"` // "result"
	Cmd   string `json:"cmd"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Output: what a read verb (logs) gives back, at most caps.MaxOutput bytes
	Output string `json:"output,omitempty"`
}

type Event struct {
	Type string `json:"type"` // "event"
	Text string `json:"text"`
	Bad  bool   `json:"bad"`
	// What it is about, for labhud to keep beside that target (all optional): Kind is "update"
	// (From and To are the image's version before and after), "crash", "oom" or "loop".
	Cap    string `json:"cap,omitempty"`
	Target string `json:"target,omitempty"`
	Kind   string `json:"kind,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// --- signed, labhud to agent ---

type Allow struct {
	Type    string              `json:"type"` // "allow"
	Caps    []string            `json:"caps"`
	Targets map[string][]string `json:"targets"`
	// Auto: the targets labhud updates on its own, on a schedule (docker containers)
	Auto map[string][]string `json:"auto,omitempty"`
}

type Command struct {
	Type   string `json:"type"` // "command"
	Cmd    string `json:"cmd"`
	Cap    string `json:"cap"`
	Verb   string `json:"verb"`
	Target string `json:"target"`
	// Auth: a registry's login for this one docker update (labhud with registries, agent with
	// the "registry-auth" feature), sealed (seal.go). Used only for an image of that registry.
	Auth *SealedAuth `json:"auth,omitempty"`
	// HoldCritical: a docker update labhud starts on its own, with "hold back an update with new
	// critical CVEs": the new image is scanned first and kept out if it has more than the old one
	HoldCritical bool `json:"hold_critical,omitempty"`
	// Files: a stack deploy's files, sealed (MaxSealedFiles): {"compose": "…", "env": "…"}
	Files *SealedFiles `json:"files,omitempty"`
}

// SealedFiles: the files of a stack, sealed, with the nonce they were sealed with.
type SealedFiles struct {
	Nonce string `json:"nonce"`
	Box   string `json:"box"`
}

// SealedAuth: the registry in clear (to check against the image before anything), the login sealed.
type SealedAuth struct {
	Registry string `json:"registry"`
	Nonce    string `json:"nonce"`
	Box      string `json:"box"`
}

// Login is a sealed Auth opened: {"username":…,"password":…}. Never logged, never written.
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Update: replace the agent's binary with that release (selfupdate). Answered by a Result with
// the same Cmd, then the agent execs the new binary and dials again with the new version.
type Update struct {
	Type    string `json:"type"` // "update"
	Cmd     string `json:"cmd"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type Bye struct {
	Type   string `json:"type"` // "bye"
	Reason string `json:"reason"`
}
