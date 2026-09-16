package domain

var operationTransitions = map[OperationStatus]map[OperationStatus]bool{
	OperationQueued: {
		OperationPreparing: true, OperationAborted: true, OperationUnknown: true,
		OperationNeedsIntervention: true,
	},
	OperationPreparing: {
		OperationExecuting: true, OperationAborted: true, OperationUnknown: true,
		OperationNeedsIntervention: true,
	},
	OperationExecuting: {
		OperationVerifying: true, OperationFailed: true, OperationUnknown: true,
		OperationRollbackRequired: true, OperationNeedsIntervention: true,
	},
	OperationVerifying: {
		OperationSucceeded: true, OperationFailed: true, OperationUnknown: true,
		OperationRollbackRequired: true, OperationNeedsIntervention: true,
	},
	OperationRollbackRequired: {
		OperationRollingBack: true, OperationNeedsIntervention: true,
	},
	OperationRollingBack: {
		OperationRolledBack: true, OperationRollbackFailed: true, OperationUnknown: true,
		OperationNeedsIntervention: true,
	},
}

func CanTransitionOperation(from, to OperationStatus) bool {
	return operationTransitions[from][to]
}

func IsTerminalOperation(status OperationStatus) bool {
	switch status {
	case OperationSucceeded, OperationFailed, OperationAborted, OperationRolledBack,
		OperationRollbackFailed, OperationNeedsIntervention:
		return true
	default:
		return false
	}
}

func VerificationAllowsSuccess(status VerificationStatus, maintenanceReleased bool) bool {
	return status == VerificationPass && maintenanceReleased
}
