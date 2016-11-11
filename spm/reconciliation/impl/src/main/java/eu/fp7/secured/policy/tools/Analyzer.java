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
package eu.fp7.secured.policy.tools;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.EmptySelectorException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotInSemiLatticeException;
import eu.fp7.secured.exception.policy.ResolutionErrorException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.PolicyConflictResult;
import eu.fp7.secured.policy.anomaly.RuleAnomalyAnalyzer;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.semilattice.Semilattice;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.action.IPSecAction;
import eu.fp7.secured.rule.action.IPSecActionSet;
import eu.fp7.secured.rule.action.IPSecActionType;
import eu.fp7.secured.rule.impl.GenericRule;

// TODO: Auto-generated Javadoc
/**
 * The Class Analyzer.
 */
public class Analyzer {

	/**
	 * Gets the single anomalies.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 * @return the single anomalies
	 */
	public Set<PolicyAnomaly> getSingleAnomalies(Policy policy, SelectorTypes selectorTypes) {
		Set<PolicyAnomaly> anomaly_list = new HashSet<PolicyAnomaly>();

		RuleAnomalyAnalyzer analyzer = new RuleAnomalyAnalyzer(policy, selectorTypes);

		LinkedList<Policy> policy_list = new LinkedList<Policy>();

		policy_list.add(policy);

		for (GenericRule r : policy.getRuleSet()) {

			HashMap<GenericRule, ConflictType> conflict_map = analyzer.getAllAnomaliesExternal(r);
			
			HashSet<GenericRule> conflist_rule_set = new HashSet<>();

			for (GenericRule rr : conflict_map.keySet()) {

				if (conflict_map.get(rr) != ConflictType.NON_CONFLICTING && conflict_map.get(rr) != ConflictType.NON_INTERSECTING
						&& conflict_map.get(rr) != ConflictType.INTERSECTING_but_NOT_CONFLICTING && conflict_map.get(rr) != ConflictType.LESS_but_NOT_CONFLICTING
						&& conflict_map.get(rr) != ConflictType.GREATER_but_NOT_CONFLICTING && conflict_map.get(rr) != ConflictType.IDENTICAL) {
					GenericRule[] rule_set = new GenericRule[2];
					rule_set[0] = r;
					rule_set[1] = rr;
					PolicyAnomaly anomaly = new PolicyAnomaly(policy_list, rule_set, conflict_map.get(rr));

					anomaly_list.add(anomaly);
					
					conflist_rule_set.add(rr);
				}
			}

			try {
				if(conflist_rule_set.size() > 1){
				GenericRule[] rule_array = conflist_rule_set.toArray(new GenericRule[conflist_rule_set.size()]);
				GenericRule[] rule_set2 = new GenericRule[rule_array.length+1];
				
				rule_set2[0] = r;
				for(int i=1; i<rule_set2.length; i++){
					rule_set2[i] = rule_array[i-1];
				}
				
				if (analyzer.isGeneralRedundant(r, rule_array)) {
					PolicyAnomaly anomaly = new PolicyAnomaly(policy_list, rule_set2, ConflictType.n_REDUNDANT);
					anomaly_list.add(anomaly);
				}

				if (analyzer.isGeneralShadowed(r, rule_array)) {
					PolicyAnomaly anomaly = new PolicyAnomaly(policy_list, rule_set2, ConflictType.n_SHADOWED);
					anomaly_list.add(anomaly);
				}
				}

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return anomaly_list;
	}

	/**
	 * Gets the distributed anomalies.
	 *
	 * @param policy the policy
	 * @param can the can
	 * @param sl the sl
	 * @return the distributed anomalies
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws ResolutionErrorException the resolution error exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws EmptySelectorException the empty selector exception
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 * @throws Exception the exception
	 */
	public Set<PolicyAnomaly> getDistributedAnomalies(ComposedPolicy policy, CanonicalForm can, Semilattice<GenericRule> sl) throws UnsupportedSelectorException,
			UnmanagedRuleException, ResolutionErrorException, NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException,
			EmptySelectorException, NotInSemiLatticeException, Exception {

		Set<PolicyAnomaly> anomaly_list = new HashSet<PolicyAnomaly>();

		for (GenericRule rule : can.getRuleSet()) {

			anomaly_list.addAll(getRuleAnomalies(can.getOriginalRules(rule), policy.getOriginalPolicy(), policy.getPolicyList(), can));

			if (rule.getAction().equals(FilteringAction.INCONSISTENT)) {

				HashSet<GenericRule> rule_collection = new HashSet<GenericRule>();

				for (GenericRule r : sl.getOutgoingAdjacentVertices(rule)) {
					if (!r.equals(sl.getTop()) && !r.equals(sl.getRoot())){
						rule_collection.add(r);
					}
				}

				if (rule_collection.size()==0 || !can.getRuleClassifier().isHidden(rule, rule_collection.toArray( new GenericRule[rule_collection.size()] ))){
					anomaly_list.add(new PolicyAnomaly(can.getOriginalRules(rule), ConflictType.INCONSISTENT));
				}

			}
		}

		return anomaly_list;
	}

	/**
	 * Gets the rule anomalies.
	 *
	 * @param rules the rules
	 * @param org_policy_list the org_policy_list
	 * @param policy_list the policy_list
	 * @param can the can
	 * @return the rule anomalies
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	private HashSet<PolicyAnomaly> getRuleAnomalies(GenericRule[] rules, List<Policy> org_policy_list, LinkedList<LinkedList<Policy>> policy_list, CanonicalForm can)
			throws NoExternalDataException, InvalidActionException {
		HashSet<PolicyAnomaly> anomalie_set = new HashSet<PolicyAnomaly>();

		HashMap<Policy, HashSet<GenericRule>> rp = new HashMap<Policy, HashSet<GenericRule>>();
		for (Policy p : org_policy_list) {
			HashSet<GenericRule> hs = new HashSet<GenericRule>();
			rp.put(p, hs);
		}

		HashSet<GenericRule> rs;
		for (GenericRule r : rules) {
			boolean found = false;
			for (Policy p : org_policy_list) {
				rs = rp.get(p);
				if (p.containsRule(r)) {
					rs.add(r);
					found = true;
				}
			}
			if (!found) {
				System.err.println("E:" + r.getName() + " : " + r.hashCode());
				throw new NoExternalDataException();
			}
		}

		int[] secLevel_list = new int[policy_list.size()];
		int i = 0;
		for (LinkedList<Policy> p_list : policy_list) {
			Action[] a_list = new Action[p_list.size()];
			int ii = 0;
			int count = 0;
			for (Policy p : p_list) {
				if (rp.get(p).isEmpty()) {
					a_list[ii++] = p.getDefaultAction();
				} else {
					count += rp.get(p).size();
					a_list[ii++] = p.getResolutionStrategy().composeActions(rp.get(p));
				}
			}

			PolicyConflictResult policy_conflict = getIPSecSerialConflict(a_list);

			secLevel_list[i++] = policy_conflict.getSecLevel();

			ConflictType conflict = policy_conflict.getConflict();
			if (conflict != ConflictType.NON_CONFLICTING)
				anomalie_set.add(new PolicyAnomaly(p_list, rules, conflict));

			if (count > 1 && a_list.length > 1) {
				GenericRule[] c_rules = new GenericRule[count];
				count--;
				for (Policy p : p_list)
					for (GenericRule r : rp.get(p))
						c_rules[count--] = r;
				if (a_list[0] == FilteringAction.DENY) {
					boolean found = false;
					for (Action a : a_list) {
						if (a != FilteringAction.DENY) {
							if(a instanceof FilteringAction)
								anomalie_set.add(new PolicyAnomaly(p_list, c_rules, ConflictType.SHADOWED));
							else
								anomalie_set.add(new PolicyAnomaly(p_list, c_rules, ConflictType.INTER_TECH_CONFLICT));
							found = true;
							break;
						}
					}
					if (!found)
						anomalie_set.add(new PolicyAnomaly(p_list, c_rules, ConflictType.REDUNDANT));
				} else if (can.getResolutionStrategy().composeActions(rules) == FilteringAction.DENY)
					anomalie_set.add(new PolicyAnomaly(p_list, c_rules, ConflictType.SPURIOUS));
			}

		}

		ConflictType conflict = getIPSecParallelConflict(secLevel_list);
		if (conflict != ConflictType.NON_CONFLICTING)
			anomalie_set.add(new PolicyAnomaly(rules, conflict));

		return anomalie_set;
	}

	/**
	 * Gets the IP sec parallel conflict.
	 *
	 * @param secLevel_list the sec level_list
	 * @return the IP sec parallel conflict
	 */
	private ConflictType getIPSecParallelConflict(int[] secLevel_list) {

		if (secLevel_list.length != 0) {
			int ii = secLevel_list[0];
			for (int i = 1; i < secLevel_list.length; i++) {
				if (ii != secLevel_list[i])
					return ConflictType.SECLEVEL_CONFLICT;
			}
		}
		return ConflictType.NON_CONFLICTING;
	}

	/**
	 * Gets the IP sec serial conflict.
	 *
	 * @param actionList the action list
	 * @return the IP sec serial conflict
	 */
	private PolicyConflictResult getIPSecSerialConflict(Action[] actionList) {
		Stack<IPSecAction> IPSecActionStack = new Stack<IPSecAction>();
		int secLevel = -1;
		ConflictType result_conflict = ConflictType.NON_CONFLICTING;

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
						if (IPSecActionStack.size() > 1)
							result_conflict = ConflictType.IPSEC_OVERLAP;

						if (IPSecActionStack.size() == 1 && a.getType() == IPSecActionType.ESP) {
							IPSecAction temp = IPSecActionStack.pop();
							if (temp.getType() == IPSecActionType.AH) {
								result_conflict = ConflictType.IPSEC_OVERLAP;
							}
							IPSecActionStack.push(temp);
						}
						IPSecActionStack.push(a);
						if (secLevel == -1)
							secLevel = 1;
					}

					if (a.getType() == IPSecActionType.INVERT_AH || a.getType() == IPSecActionType.INVERT_ESP) {
						if (!IPSecActionStack.isEmpty()) {
							IPSecAction temp = IPSecActionStack.pop();
							if (!temp.isInvertEqual(a))
								return new PolicyConflictResult(ConflictType.IPSEC_INCONSISTENT, secLevel);
						} else
							return new PolicyConflictResult(ConflictType.IPSEC_INCONSISTENT, secLevel);
					}
				}

			} else {
				if (IPSecActionStack.isEmpty())
					secLevel = 0;
			}
			if (action == FilteringAction.DENY)
				return new PolicyConflictResult(result_conflict, secLevel);
		}

		if (IPSecActionStack.isEmpty())
			return new PolicyConflictResult(result_conflict, secLevel);
		else
			return new PolicyConflictResult(ConflictType.IPSEC_INCONSISTENT, secLevel);

	}

}
