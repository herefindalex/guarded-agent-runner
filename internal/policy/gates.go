package policy

import "guarded-agent-runner/internal/domain"

type ReleaseMode string

const (
	ModeReadOnly ReleaseMode = "READ_ONLY"
	ModeShadow   ReleaseMode = "SHADOW_ONLY"
	ModeMutation ReleaseMode = "MUTATION"
)

type SupportProfile struct {
	ProfileID string                       `json:"profile_id"`
	Mode      ReleaseMode                  `json:"mode"`
	Gates     map[string]domain.GateStatus `json:"gates"`
}

var RequiredMutationGates = []string{"G-01", "G-02", "G-03", "G-04", "G-05", "G-06", "G-07"}

func DefaultM1Profile() SupportProfile {
	gates := make(map[string]domain.GateStatus, len(RequiredMutationGates))
	for _, gate := range RequiredMutationGates {
		gates[gate] = domain.GateNotRun
	}
	return SupportProfile{ProfileID: "gar-v0.1-m1-fake", Mode: ModeShadow, Gates: gates}
}

func (profile SupportProfile) MutationAllowed() bool {
	if profile.Mode != ModeMutation {
		return false
	}
	for _, gate := range RequiredMutationGates {
		if profile.Gates[gate] != domain.GatePass {
			return false
		}
	}
	return true
}
