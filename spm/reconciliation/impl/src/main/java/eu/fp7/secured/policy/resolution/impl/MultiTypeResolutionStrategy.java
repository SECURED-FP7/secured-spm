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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Class MultiTypeResolutionStrategy.
 */
public class MultiTypeResolutionStrategy extends GenericConflictResolutionStrategy {

	/** The Constant label. */
	private static final String label = "MultiTypeResolutionStrategy";
	
	/** The Constant label_simple. */
	private static final String label_simple = "MTRS";
	
	/** The policy_list. */
	private LinkedList<Policy> policy_list;
	
	/** The default action. */
	private Action defaultAction;

	/**
	 * Instantiates a new multi type resolution strategy.
	 *
	 * @param policy_list the policy_list
	 * @param defaultAction the default action
	 */
	public MultiTypeResolutionStrategy(LinkedList<Policy> policy_list, Action defaultAction) {
		this.policy_list = policy_list;
		this.defaultAction = defaultAction;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException, IncompatibleExternalDataException, InvalidActionException {
		GenericRule[] rules=new GenericRule[2];
		rules[1]=r1;
		rules[2]=r2;
		return composeActions(rules);
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule[])
	 */
	@Override
	public Action composeActions(GenericRule[] rules) throws NoExternalDataException, InvalidActionException{
		if(rules.length == 0)
			return defaultAction;
		
		HashMap<Policy, HashSet<GenericRule>> rp = new HashMap<Policy, HashSet<GenericRule>>();
		


		for(Policy p:policy_list){
			HashSet<GenericRule> hs = new HashSet<GenericRule>();
			rp.put(p, hs);
		}
		
		boolean found=false;
		for(GenericRule r: rules){
			found=false;
			for(Policy p:policy_list){
				HashSet<GenericRule> rs=rp.get(p);
				if(p.containsRule(r)){
					rs.add(r);
					found=true;
				}
			}
			if(!found){
				System.out.println("E:"+r.getName()+" : "+r.hashCode());
				throw new NoExternalDataException();
			}
		}
		
		for(Policy p:policy_list){
			if(!rp.get(p).isEmpty()){
//				System.out.println();
//				System.out.println(p.getName());
//				System.out.println(rp.get(p));
//				System.out.println(p.getResolutionStrategy().composeActions(rp.get(p)));
//				System.out.println();
				return p.getResolutionStrategy().composeActions(rp.get(p));
			}
		}

		return defaultAction;
		
	
	}

	
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#compare(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		
		for(Policy p:policy_list){
			
			if(p.containsRule(r1) && p.containsRule(r2))
				return p.getResolutionStrategy().compare(r1, r2);
		}
		
		return ResolutionComparison.DIFFERENT_SET;

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
		MultiTypeResolutionStrategy res = new MultiTypeResolutionStrategy(policy_list, defaultAction);
		
		return res;
	}
	
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#toString()
	 */
	@Override
	public String toString(){
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
