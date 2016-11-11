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
import java.util.List;
import java.util.Stack;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.mspl.EnableActionType;
import eu.fp7.secured.mspl.ReduceBandwidthActionType;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.AnonimityAction;
import eu.fp7.secured.rule.action.DataProtAction;
import eu.fp7.secured.rule.action.EnableAction;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.action.IPSecAction;
import eu.fp7.secured.rule.action.IPSecActionSet;
import eu.fp7.secured.rule.action.IPSecActionType;
import eu.fp7.secured.rule.action.LoggingAction;
import eu.fp7.secured.rule.action.ParentalAction;
import eu.fp7.secured.rule.action.ReduceBandwidthAction;
import eu.fp7.secured.rule.impl.GenericRule;

// TODO: Auto-generated Javadoc
/**
 * The Class ComposedResolutionStrategy.
 */
public class ComposedResolutionStrategy extends GenericConflictResolutionStrategy {
	
	/** The Constant label. */
	private static final String label = "ComposedResolutionStrategy";
	
	/** The Constant label_simple. */
	private static final String label_simple = "CompRS";

	/** The policy_list. */
	private LinkedList<LinkedList<Policy>> policy_list;

	/** The org_policy_list. */
	private List<Policy> org_policy_list;

	/**
	 * Instantiates a new composed resolution strategy.
	 *
	 * @param policy_list the policy_list
	 * @param org_policy_list the org_policy_list
	 */
	public ComposedResolutionStrategy(LinkedList<LinkedList<Policy>> policy_list, List<Policy> org_policy_list) {
		this.policy_list = policy_list;
		this.org_policy_list = org_policy_list;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.polito.policyManagement.policy.resolution.
	 * GenericConflictResolutionStrategy#cloneResolutionStrategy()
	 */
	@Override
	public GenericConflictResolutionStrategy cloneResolutionStrategy() {
		return new ComposedResolutionStrategy(policy_list, org_policy_list);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.polito.policyManagement.policy.resolution.
	 * GenericConflictResolutionStrategy
	 * #compare(org.polito.ruleManagement.generalized.GenericRule,
	 * org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		for (Policy p : org_policy_list) {
			if (p.containsRule(r1) && p.containsRule(r2))
				return p.getResolutionStrategy().compare(r1, r2);
		}

		return ResolutionComparison.DIFFERENT_SET;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.polito.policyManagement.policy.resolution.
	 * GenericConflictResolutionStrategy
	 * #composeActions(org.polito.ruleManagement.generalized.GenericRule,
	 * org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException, IncompatibleExternalDataException, InvalidActionException {

		GenericRule[] rules = new GenericRule[2];

		rules[0] = r1;
		rules[1] = r2;

		return composeActions(rules);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.polito.policyManagement.policy.resolution.
	 * GenericConflictResolutionStrategy
	 * #composeActions(org.polito.ruleManagement.generalized.GenericRule[])
	 */
	@Override
	public Action composeActions(GenericRule[] rules) throws NoExternalDataException, InvalidActionException {

		HashMap<Policy, HashSet<GenericRule>> rp = new HashMap<Policy, HashSet<GenericRule>>();

		for (Policy p : org_policy_list) {
			HashSet<GenericRule> hs = new HashSet<GenericRule>();
			rp.put(p, hs);
		}

		boolean found = false;
		for (GenericRule r : rules) {
			found = false;
			for (Policy p : org_policy_list) {
				HashSet<GenericRule> rs = rp.get(p);
				if (p.containsRule(r)) {
					rs.add(r);
					found = true;
				}
			}
			if (!found) {
				System.out.println("E:" + r.getName() + " : " + r.hashCode());
				throw new NoExternalDataException();
			}
		}

		int i = 0;
		Action[] action_list = new Action[policy_list.size()];
		for (LinkedList<Policy> p_list : policy_list) {
			Action[] a_list = new Action[p_list.size()];
			int ii = 0;
			for (Policy p : p_list) {
				if (rp.get(p).isEmpty())
					a_list[ii++] = p.getDefaultAction();
				else
					a_list[ii++] = p.getResolutionStrategy().composeActions(rp.get(p));
			}
			action_list[i++] = getSerialAction(a_list);
		}

		return getParallelAction(action_list);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.polito.policyManagement.policy.resolution.
	 * GenericConflictResolutionStrategy
	 * #isActionEquivalent(org.polito.ruleManagement.generalized.GenericRule,
	 * org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public boolean isActionEquivalent(GenericRule r1, GenericRule r2) {
		return r1.getAction().equals(r2.getAction());
	}

	/**
	 * Gets the default action.
	 *
	 * @return the default action
	 */
	public Action getDefaultAction() {
		Action[] action_list = new Action[policy_list.size()];
		int i = 0;
		for (LinkedList<Policy> p_list : policy_list) {
			Action[] a_list = new Action[p_list.size()];
			int ii = 0;
			for (Policy p : p_list) {
				a_list[ii++] = p.getDefaultAction();
			}
			action_list[i++] = getSerialAction(a_list);
		}
		return getParallelAction(action_list);
	}

	/**
	 * Gets the serial action.
	 *
	 * @param actionList the action list
	 * @return the serial action
	 */
	private Action getSerialAction(Action[] actionList) {
		Stack<IPSecAction> IPSecActionStack = new Stack<IPSecAction>();
		boolean logging = false;
		boolean enable = false;
		boolean bandwith = false;
		boolean parental = false;
		boolean anonimity = false;
		
		double up = Integer.MAX_VALUE;
		double down = Integer.MAX_VALUE;

		int interval = Integer.MAX_VALUE;
		int threshold = Integer.MAX_VALUE;
		String event = "";
		
		EnableActionType actionType = null;
		ParentalAction parentalAction = null;
		AnonimityAction anonimityAction = null;

		for (Action action : actionList) {
			if (action instanceof IPSecAction || action instanceof IPSecActionSet) {

				LinkedList<IPSecAction> ipsecactionlist;
				if (action instanceof IPSecAction) {
					ipsecactionlist = new LinkedList<IPSecAction>();
					ipsecactionlist.add((IPSecAction) action);
				} else
					ipsecactionlist = ((IPSecActionSet) action).getSecActionList();

				for (IPSecAction a : ipsecactionlist) {
					if (a.getType() == IPSecActionType.AH || a.getType() == IPSecActionType.ESP) {
						IPSecActionStack.push(a);
					}

					if (a.getType() == IPSecActionType.INVERT_AH || a.getType() == IPSecActionType.INVERT_ESP) {
						if (!IPSecActionStack.isEmpty()) {
							IPSecAction temp = IPSecActionStack.pop();
							if (!temp.isInvertEqual(a))
								return FilteringAction.DUMMY;
						} else
							return FilteringAction.DUMMY;
					}
				}

			}
			
			if (action instanceof LoggingAction){
				logging = true;
				event = ((LoggingAction) action).getEvent();
				
				if(interval>((LoggingAction) action).getInterval())
					interval = ((LoggingAction) action).getInterval();
				
				if(threshold>((LoggingAction) action).getThreshold())
					threshold = ((LoggingAction) action).getThreshold();
				
			}
			
			if (action instanceof EnableAction){
				enable = true;
				if(actionType==null)					
					actionType = ((EnableAction) action).getActionType();
				else{
					if(((EnableAction) action).getActionType().isEnable()){
						actionType = ((EnableAction) action).getActionType();
					}
				}
			}
			
			if (action instanceof ParentalAction){
				parental = true;
				parentalAction = (ParentalAction)action;
			}
			
			if (action instanceof AnonimityAction){
				anonimity = true;
				anonimityAction = (AnonimityAction)action;
			}
			
			if (action instanceof ReduceBandwidthAction){
				bandwith = true;
				
				if(up>((ReduceBandwidthAction) action).getActionType().getUplinkBandwidthValue()){
					up = ((ReduceBandwidthAction) action).getActionType().getUplinkBandwidthValue();
				}
				if(down>((ReduceBandwidthAction) action).getActionType().getDownlinkBandwidthValue()){
					down = ((ReduceBandwidthAction) action).getActionType().getDownlinkBandwidthValue();
				}
			}
			
			if (action instanceof DataProtAction){
				return action;
			}

			if (action == FilteringAction.DENY)
				return FilteringAction.DENY;
		}
		
		if(logging)
			return new LoggingAction(event, interval, threshold);
		
		if(bandwith){
			ReduceBandwidthActionType at = new ReduceBandwidthActionType();
			at.setDownlinkBandwidthValue(down);
			at.setUplinkBandwidthValue(up);
			return new eu.fp7.secured.rule.action.ReduceBandwidthAction(at);
		}
		
		if(enable){
			return new EnableAction(actionType);
		}
		
		if(parental){
			return parentalAction;
		}
		
		if(anonimity){
			return anonimityAction;
		}

		if (IPSecActionStack.isEmpty())
			return FilteringAction.ALLOW;
		else
			return FilteringAction.DUMMY;

	}

	/**
	 * Gets the parallel action.
	 *
	 * @param actionList the action list
	 * @return the parallel action
	 */
	private Action getParallelAction(Action[] actionList) {
		Action action = actionList[0];

		for (Action a : actionList) {
			if (!(action.equals(a)))
				return FilteringAction.INCONSISTENT;
		}

		
		
		return action;
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
