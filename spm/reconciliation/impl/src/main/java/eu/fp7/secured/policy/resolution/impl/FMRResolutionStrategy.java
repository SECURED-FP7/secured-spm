/*******************************************************************************
 * Copyright (c) 2015 Politecnico di Torino.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     TorSec - SECURED Team - initial API and implementation
 ******************************************************************************/
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

/**
 * The Class FMRResolutionStrategy.
 */
public class FMRResolutionStrategy extends ExternalDataResolutionStrategy<GenericRule, Integer> {

	/** The Constant label. */
	private static final String label = "First Matching Rule (FMR)";
	
	/** The Constant label_simple. */
	private static final String label_simple = "FMR";

	/** The priorities. */
	ExternalDataManager<GenericRule, Integer> priorities;

	/**
	 * Instantiates a new FMR resolution strategy.
	 */
	public FMRResolutionStrategy() {
		this.priorities = new UniqueValueExternalDataManager<GenericRule, Integer>();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
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

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule[])
	 */
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

	/**
	 * Compose actions no c heck.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the action
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 */
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

	/**
	 * Compose external data no check.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the integer
	 */
	private Integer composeExternalDataNoCheck(GenericRule r1, GenericRule r2) {
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		return p1 < p2 ? p1 : p2;

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#composeExternalData(java.lang.Object, java.lang.Object)
	 */
	@Override
	public Integer composeExternalData(GenericRule r1, GenericRule r2) throws NoExternalDataException {
		if (!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();
		Integer p1 = priorities.getExternalData(r1);
		Integer p2 = priorities.getExternalData(r2);
		return p1 < p2 ? p1 : p2;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#composeExternalData(java.lang.Object[])
	 */
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

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#compare(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
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

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#isActionEquivalent(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public boolean isActionEquivalent(GenericRule r1, GenericRule r2) {
		return r1.getAction().equals(r2.getAction());
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#cloneResolutionStrategy()
	 */
	@Override
	public GenericConflictResolutionStrategy cloneResolutionStrategy() {
		FMRResolutionStrategy res = new FMRResolutionStrategy();
		res.priorities = priorities.cloneExternalDataManager();

		return res;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#toString()
	 */
	@Override
	public String toString() {
		return label;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		return label_simple;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#setExternalData(java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setExternalData(GenericRule rule, Integer externalData) throws DuplicateExternalDataException {
		priorities.setExternalData(rule, externalData);

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#getExternalData(java.lang.Object)
	 */
	@Override
	public Integer getExternalData(GenericRule rule) {
		return priorities.getExternalData(rule);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#clearExternalData(java.lang.Object)
	 */
	@Override
	public void clearExternalData(GenericRule rule) {
		priorities.clearExternalData(rule);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#isRuleManaged(java.lang.Object)
	 */
	@Override
	public boolean isRuleManaged(GenericRule rule) {
		return priorities.isRuleManaged(rule);
	}

}
