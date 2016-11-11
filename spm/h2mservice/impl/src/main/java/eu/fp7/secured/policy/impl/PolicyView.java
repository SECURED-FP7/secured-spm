// TODO: evaluate if this class is still needed

package eu.fp7.secured.policy.impl;

import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.utils.PolicyType;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;

public class PolicyView extends PolicyImpl {

	private ConditionClause	conditionClause;

	public PolicyView(GenericConflictResolutionStrategy resolutionStrategy, Action defaultAction, ConditionClause conditionClause, PolicyType policyType, String name) throws NoExternalDataException {

		super(resolutionStrategy, defaultAction, policyType, name);
		this.conditionClause = conditionClause;
	}

	public ConditionClause getConditionClause() {
		return this.conditionClause;
	}

}
