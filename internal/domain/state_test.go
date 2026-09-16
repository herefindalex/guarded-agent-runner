package domain

import "testing"

func TestUnknownDoesNotReleaseOrAdvance(t *testing.T) {
	if CanTransitionOperation(OperationUnknown, OperationExecuting) {
		t.Fatal("UNKNOWN must not advance to another mutation step")
	}
	if IsTerminalOperation(OperationUnknown) {
		t.Fatal("UNKNOWN must retain ownership until reconcile or takeover")
	}
}

func TestSuccessRequiresVerificationPassAndRelease(t *testing.T) {
	if VerificationAllowsSuccess(VerificationInconclusive, true) {
		t.Fatal("INCONCLUSIVE cannot become success")
	}
	if VerificationAllowsSuccess(VerificationPass, false) {
		t.Fatal("PASS without maintenance release cannot become success")
	}
	if !VerificationAllowsSuccess(VerificationPass, true) {
		t.Fatal("PASS plus confirmed release should satisfy success precondition")
	}
}
