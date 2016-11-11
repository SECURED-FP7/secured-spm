package eu.fp7.secured.policy.resolution.impl;

import java.util.Collection;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.externaldata.ExternalDataManager;
import eu.fp7.secured.policy.externaldata.UniqueValueExternalDataManager;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;

public class FMRResolutionStrategy extends ExternalDataResolutionStrategy<GenericRule, Integer> {

	private static final String label = "First Matching Rule (FMR)";
	private static final String label_simple = "FMR";

	ExternalDataManager<GenericRule, Integer> priorities;

	public FMRResolutionStrategy() {
		this.priorities = new UniqueValueExternalDataManager<GenericRule, Integer>();
	}

	@Override
	public Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException, IncompatibleExternalDataException {
		if (!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		if (p1 < p2)
			return r1.getAction();
		else if (p1 > p2)
			return r2.getAction();
		else if (!r1.getAction().equals(r2.getAction()))
			throw new IncompatibleExternalDataException();
		else
			return r1.getAction();
	}

	@Override
	public Action composeActions(GenericRule[] rules) throws NoExternalDataException {
		if (rules.length == 0)
			return null;
		Integer[] p = new Integer[rules.length];
		int i = 0, imin = -1;
		int min = Integer.MAX_VALUE;
		for (GenericRule rule : rules) {
			if (!priorities.isRuleManaged(rule)) {
				throw new NoExternalDataException();
			}
			p[i] = priorities.getExternalData(rule);
			if (p[i] < min) {
				min = p[i];
				imin = i;
			}
			i++;
		}
		return rules[imin].getAction();
	}

	private Action composeActionsNoCHeck(GenericRule r1, GenericRule r2) throws IncompatibleExternalDataException {
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		if (p1 < p2)
			return r1.getAction();
		else if (p1 > p2)
			return r2.getAction();
		else if (!r1.getAction().equals(r2.getAction()))
			throw new IncompatibleExternalDataException();
		else
			return r1.getAction();
	}

	private Integer composeExternalDataNoCheck(GenericRule r1, GenericRule r2) {
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		return p1 < p2 ? p1 : p2;

	}

	@Override
	public Integer composeExternalData(GenericRule r1, GenericRule r2) throws NoExternalDataException {
		if (!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		return p1 < p2 ? p1 : p2;
	}

	@Override
	public Integer composeExternalData(GenericRule[] rules) throws NoExternalDataException {
		Integer[] p = new Integer[rules.length];
		int i = 0;
		Integer min = Integer.MAX_VALUE;
		for (GenericRule rule : rules) {
			if (!priorities.isRuleManaged(rule)) {
				throw new NoExternalDataException();
			}
			p[i] = priorities.getExternalData(rule);
			if (p[i] < min) {
				min = p[i];
				// imin=i;
			}
			i++;
		}
		return min;
	}

	@Override
	public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException {
		if (!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();
		int p1 = priorities.getExternalData(r1);
		int p2 = priorities.getExternalData(r2);

		if (p1 < p2)
			return ResolutionComparison.UNIVERSALLY_GREATER;
		if (p1 == p2)
			return ResolutionComparison.EQUIVALENT;
		else
			return ResolutionComparison.UNIVERSALLY_LESS;
	}

	@Override
	public boolean isActionEquivalent(GenericRule r1, GenericRule r2) {
		return r1.getAction().equals(r2.getAction());
	}

	@Override
	public GenericConflictResolutionStrategy cloneResolutionStrategy() {
		FMRResolutionStrategy res = new FMRResolutionStrategy();
		res.priorities = priorities.cloneExternalDataManager();

		return res;
	}

	@Override
	public String toString() {
		return label;
	}
	
	@Override
	public String toSimpleString() {
		return label_simple;
	}

	@Override
	public void setExternalData(GenericRule rule, Integer externalData) throws DuplicateExternalDataException {
		priorities.setExternalData(rule, externalData);

	}

	@Override
	public Integer getExternalData(GenericRule rule) {
		return priorities.getExternalData(rule);
	}

	@Override
	public void clearExternalData(GenericRule rule) {
		priorities.clearExternalData(rule);
	}

	@Override
	public boolean isRuleManaged(GenericRule rule) {
		return priorities.isRuleManaged(rule);
	}

}
