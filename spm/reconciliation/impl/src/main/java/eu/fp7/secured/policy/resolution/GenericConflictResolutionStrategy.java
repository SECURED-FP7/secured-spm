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
package eu.fp7.secured.policy.resolution;

import java.util.List;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;

/**
 * The Class GenericConflictResolutionStrategy.
 */
public abstract class GenericConflictResolutionStrategy {
	
	/**
	 * Clones the resolution strategy.
	 *
	 * @return the generic conflict resolution strategy
	 */
	public abstract GenericConflictResolutionStrategy cloneResolutionStrategy();

	/**
	 * Compare.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the resolution comparison
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicatedRuleException the duplicated rule exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	public abstract ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException;

	/**
	 * Compose actions.
	 *
	 * @param rules the rules
	 * @return the action
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public Action composeActions(Collection<GenericRule> rules) throws NoExternalDataException, InvalidActionException{
		return composeActions(rules.toArray(new GenericRule[rules.size()]));
	}
	
	/**
	 * Compose actions.
	 *
	 * @param rules the rules
	 * @param r the r
	 * @return the action
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public Action composeActions(Collection<GenericRule> rules, GenericRule r)	throws NoExternalDataException, InvalidActionException {
		GenericRule[] rule_set = rules.toArray(new GenericRule[rules.size()+1]);
		rule_set[rules.size()]=r;
		return composeActions(rule_set);
	}

	/**
	 * Compose actions.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the action
	 * @throws NoExternalDataException the no external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public abstract Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException, IncompatibleExternalDataException, InvalidActionException;

	/**
	 * Compose actions.
	 *
	 * @param rules the rules
	 * @return the action
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public abstract Action composeActions(GenericRule[] rules) throws NoExternalDataException, InvalidActionException;

	/**
	 * Compose rules.
	 *
	 * @param rules the rules
	 * @return the generic rule
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public GenericRule composeRules(Collection<GenericRule> rules) throws NoExternalDataException, InvalidActionException{
		return composeRules((GenericRule[])rules.toArray());
	}

	/**
	 * Compose rules.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the generic rule
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public GenericRule composeRules(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException {

		ConditionClause cc_clone = r1.getConditionClause().conditionClauseClone();

		cc_clone.intersection(r2.getConditionClause());
		
		HashSet<String> MSPLs = r1.getMSPL_id();
		MSPLs.addAll(r2.getMSPL_id());
		List<HSPL> HSPLs = r1.getHSPLs();
		HSPLs.addAll(r2.getHSPLs());

		return new GenericRule(this.composeActions(r1, r2), cc_clone, r1.getName() + "-" + r2.getName(), MSPLs, HSPLs);
	}

	/**
	 * Compose rules.
	 *
	 * @param rules the rules
	 * @return the generic rule
	 * @throws InvalidActionException the invalid action exception
	 * @throws NoExternalDataException the no external data exception
	 */
	public GenericRule composeRules(GenericRule[] rules) throws InvalidActionException, NoExternalDataException {
		int length = rules.length;
		ConditionClause cc_clone = rules[0].getConditionClause().conditionClauseClone();

		String name = rules[0].getName();
		

		HashSet<String> MSPLs = new HashSet<>();		
		List<HSPL> HSPLs = new LinkedList();
		

		for (int i = 1; i < length; i++) {
			cc_clone.intersection(rules[i].getConditionClause());
			name = name + "-" + rules[i].getName();
			MSPLs.addAll(rules[i].getMSPL_id());
			HSPLs.addAll(rules[i].getHSPLs());
		}

		return new GenericRule(this.composeActions(rules), cc_clone, name, MSPLs, HSPLs);
	}

	/**
	 * Checks if is action equivalent.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return true, if is action equivalent
	 */
	public abstract boolean isActionEquivalent(GenericRule r1, GenericRule r2);

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public abstract String toString();

	/**
	 * To simple string.
	 *
	 * @return the string
	 */
	public abstract String toSimpleString();

	
}