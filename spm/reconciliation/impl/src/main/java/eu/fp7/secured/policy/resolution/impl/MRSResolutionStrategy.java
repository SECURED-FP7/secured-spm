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
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.externaldata.ExternalDataManager;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Class MRSResolutionStrategy.
 */
public class MRSResolutionStrategy extends ExternalDataResolutionStrategy<GenericRule, MRSExternalData> {

	/** The Constant label. */
	private static final String label = "MSR-GRS-LRS Resolution Strategy";
	
	/** The Constant label_simple. */
	private static final String label_simple = "MRS";
	
	/** The priorities. */
	ExternalDataManager<GenericRule, MRSExternalData> priorities;
	
	/**
	 * Instantiates a new MRS resolution strategy.
	 */
	public MRSResolutionStrategy() {
		this.priorities = new ExternalDataManager<GenericRule, MRSExternalData>();
	}
	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException {
		if(!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
				throw new NoExternalDataException();
		
		int res = compareRules(r1, r2);
		
		switch (res) {
		case -1:
			return r1.getAction();
		
		case 1:
			return r2.getAction();
		}

		//From here res==0
		
		return r1.getAction();

	}

	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule[])
	 */
	@Override
	public Action composeActions(GenericRule[] rules) throws NoExternalDataException {
		if (rules==null)
			throw new NullPointerException();
		
		if (rules.length<=0)
			throw new Error("No rules in array");
		
		GenericRule min = rules[0];
		
		for (GenericRule r : rules) {
			if(!(priorities.isRuleManaged(r)))
				throw new NoExternalDataException();
			
			if (compareRules(min,r)==1)
				min = r;
		}
		
		return min.getAction();
	}
	
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#compare(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		
		if(!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();

		
		int res = compareRules(r1, r2);
		
		switch (res) {
		case -1:
			return ResolutionComparison.UNIVERSALLY_GREATER;
		
		case 1:
			return ResolutionComparison.UNIVERSALLY_LESS;
		}

		//From here res==0

		return ResolutionComparison.EQUIVALENT;
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
		MRSResolutionStrategy clone = new MRSResolutionStrategy();
		clone.priorities = priorities.cloneExternalDataManager();
		return clone;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#composeExternalData(java.lang.Object, java.lang.Object)
	 */
	@Override
	public MRSExternalData composeExternalData(GenericRule r1, GenericRule r2) throws NoExternalDataException {
		if(!(priorities.isRuleManaged(r1) && priorities.isRuleManaged(r2)))
			throw new NoExternalDataException();
		
		int res = compareRules(r1, r2);
		
		switch (res) {
		case -1:
			return priorities.getExternalData(r1).clone();
		
		case 1:
			return priorities.getExternalData(r2).clone();
		}

		//From here res==0	
		
		return priorities.getExternalData(r2).clone();	
	}


	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#composeExternalData(java.lang.Object[])
	 */
	@Override
	public MRSExternalData composeExternalData(GenericRule[] rules) throws NoExternalDataException {
		if (rules==null)
			throw new Error("No rules in array");;
		
		if (rules.length<=0)
			throw new Error("No rules in array");
		
		GenericRule min = rules[0];
		
		for (GenericRule r : rules) {
			if(!(priorities.isRuleManaged(r)))
				throw new NoExternalDataException();
			
			if (compareRules(min,r)==1)
				min = r;
		}
		
		return priorities.getExternalData(min).clone();
	}

	
	/**
	 * Compare rules.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the int
	 */
	private int compareRules(GenericRule r1, GenericRule r2){
		
		MRSExternalData p1 = priorities.getExternalData(r1);
		MRSExternalData p2 = priorities.getExternalData(r2);
		
		if(p1.set==p2.set)
			if(p1.internalPriority<p2.internalPriority)
				return -1;
			else if (p2.internalPriority<p1.internalPriority)
				return 1;
			else return 0;
				
//				if(r1.getAction().equals(r2.getAction()))
//				return 0;
//			else if(r1.getAction().equals(FilteringAction.DENY))
//				return -1;
//			else return 1;
		
		//Case of different set
		if(p1.set==SetEnum.MRS)
			return -1;
		
		if(p2.set==SetEnum.MRS)
			return 1;
		
		//Now we check if in the case that one rule belongs to GRS and the other one 
		//belongs to LRSi
		
		if (p1.set==SetEnum.GRS) 
			if (r2.isConditionSubset(r1))
				return 1;
			else if (r1.isConditionSubsetOrEquivalent(r2))
				return -1;
		
		if (p2.set==SetEnum.GRS) 
			if (r1.isConditionSubset(r2))
				return -1;
			else if (r2.isConditionSubsetOrEquivalent(r1))
				return 1;
		
		//DTP
		if(r1.getAction().equals(r2.getAction())) 
			return 0;	
		
		if (r1.getAction().equals(FilteringAction.DENY)) 
			return -1;
		
		return 1;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#setExternalData(java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setExternalData(GenericRule rule, MRSExternalData externalData)	throws DuplicateExternalDataException {
		priorities.setExternalData(rule, externalData);
		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy#getExternalData(java.lang.Object)
	 */
	@Override
	public MRSExternalData getExternalData(GenericRule rule) {
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
}
