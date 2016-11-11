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
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.action.IPSecAction;
import eu.fp7.secured.rule.action.IPSecActionSet;
import eu.fp7.secured.rule.action.IPSecActionType;
import eu.fp7.secured.rule.impl.GenericRule;

// TODO: Auto-generated Javadoc
/**
 * The class ComposedResolutionStrategy implements the interface
 * GenericConflictResolutionStrategy. It has two private member variables
 * policy_list and org_policy_list.
 */
public class ComposedResolutionStrategy extends GenericConflictResolutionStrategy {
	
	private static final String label = "ComposedResolutionStrategy";
	private static final String label_simple = "CompRS";

	/** The member variable policy\_list is a list of the composed policies. */
	private LinkedList<LinkedList<Policy>> policy_list;

	/**
	 * The member variable org\_policy\_list is a list of all original policies
	 * from which the composed policy is composed.
	 */
	private List<Policy> org_policy_list;

	/**
	 * Instantiates a new composed resolution strategy.
	 * 
	 * @param policy_list
	 *            is a LinkedList of LinkedLists of Policies.
	 * @param org_policy_list
	 *            is a list of all original policies from which the composed
	 *            policy is composed
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
	 * Calculates the default action for the composed policy, for every list in
	 * the policy list it caluclates the serial action. All serial actions are
	 * composed parallel, the resulting action is returned.
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
	 * The function getSerialAction() accepts an array of action and calculates
	 * the serial action. If the array contains one deny action it returns
	 * FilteringAction.DENY. IPsecActions are also considered, the function can
	 * handle AH and ESP transport mode IPSec informations. If IPsec actions are
	 * open or closed in the wrong order or with the wrong hash the function
	 * returns FilteringAction.DUMMY.
	 * 
	 * @param actionList
	 *            the action list
	 * @return the serial action
	 */
	private Action getSerialAction(Action[] actionList) {
		Stack<IPSecAction> IPSecActionStack = new Stack<IPSecAction>();

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

			if (action == FilteringAction.DENY)
				return FilteringAction.DENY;
		}

		if (IPSecActionStack.isEmpty())
			return FilteringAction.ALLOW;
		else
			return FilteringAction.DUMMY;

	}

	/**
	 * The function getParallelAction() accepts an array of actions and
	 * calculates the parallel action. If all actions in the array are equal the
	 * action is returned otherwise the function returns
	 * FilteringAction.INCONSISTENT.
	 * 
	 * @param actionList
	 *            the action list
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

	@Override
	public String toString() {
		return label;
	}

	
	@Override
	public String toSimpleString() {
		return label_simple;
	}
}
