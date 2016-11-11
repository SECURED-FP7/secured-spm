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



import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.EmptySelectorException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotInSemiLatticeException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalFormGenerator;
import eu.fp7.secured.policy.translation.semilattice.SemiLatticeGenerator;
import eu.fp7.secured.policy.translation.semilattice.Semilattice;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.GenericRule;


// TODO: Auto-generated Javadoc
/**
 * The Class PolicyComparator.
 */
public class PolicyComparator {

	
	/** The can. */
	private CanonicalForm can;
	
	/** The sl. */
	private Semilattice<GenericRule> sl;

	/**
	 * Compare.
	 *
	 * @param policy1 the policy1
	 * @param policy2 the policy2
	 * @param selectorTypes the selector types
	 * @return the sets the
	 * @throws Exception the exception
	 */
	public Set<Semilattice<GenericRule>> compare(Policy policy1, Policy policy2, SelectorTypes selectorTypes) throws Exception{
		
		LinkedList<LinkedList<Policy>> policy_list = new LinkedList<LinkedList<Policy>>();
		
		LinkedList<Policy> pl1 = new LinkedList<Policy>();
		pl1.add(policy1);
		policy_list.add(pl1);
		
		LinkedList<Policy> pl2 = new LinkedList<Policy>();
		pl2.add(policy2);
		policy_list.add(pl2);
		
		ComposedPolicy policy = new ComposedPolicy(policy_list, new LinkedList<Capability>(), policy1.getName()+"_||_"+policy2.getName(), "COMPARATOR");
		
		can = CanonicalFormGenerator.getInstance(policy, selectorTypes).getCanonicalForm();
		SemiLatticeGenerator slgen = new SemiLatticeGenerator();
		slgen.generateSemilattice(can);
		sl = can.getSemiLattice();
		
		return getDifferences();
	}
	
	/**
	 * Checks if is equal.
	 *
	 * @return the boolean
	 * @throws Exception the exception
	 */
	private Boolean isEqual() throws Exception{
		
		for(GenericRule rule:can.getRuleSet())
			if(rule.getAction().equals(FilteringAction.INCONSISTENT)){
				
				
				Collection<GenericRule> rule_collection = new HashSet<GenericRule>();
				
				for(GenericRule r:sl.getOutgoingAdjacentVertices(rule)){
					if(!r.equals(sl.getTop()))
						rule_collection.add(r);
				}
				
				
				if(!can.getRuleClassifier().isHidden(rule,(GenericRule[])rule_collection.toArray()))
					return false;
			//	else
				//	rule.setAction(FilteringAction.HIDDEN_INCONSISTENT);
			}
			
		return true;
	}

	/**
	 * Gets the differences.
	 *
	 * @return the differences
	 * @throws Exception the exception
	 */
	private Set<Semilattice<GenericRule>> getDifferences() throws Exception{
		
		HashSet<Semilattice<GenericRule>> set = new HashSet<Semilattice<GenericRule>>();
		
		SemiLatticeGenerator SL_gen = new SemiLatticeGenerator();
		
		for(GenericRule rule:getMinInconsistent()){
			set.add(SL_gen.getSubSemiLattice(sl, rule));
		}
		
		return set; 
	}

	
	/**
	 * Gets the min inconsistent.
	 *
	 * @return the min inconsistent
	 * @throws Exception the exception
	 */
	private HashSet<GenericRule> getMinInconsistent()throws Exception{
		return getMinInconsistentRec(sl.getOutgoingAdjacentVertices(sl.getRoot()), sl);
	}
	
	/**
	 * Gets the min inconsistent rec.
	 *
	 * @param rule_list the rule_list
	 * @param sl the sl
	 * @return the min inconsistent rec
	 * @throws EmptySelectorException the empty selector exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicatedRuleException the duplicated rule exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	private HashSet<GenericRule> getMinInconsistentRec(List<GenericRule> rule_list, Semilattice<GenericRule> sl) throws EmptySelectorException, UnsupportedSelectorException, NotInSemiLatticeException, NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException{
		HashSet<GenericRule> rule_set = new HashSet<GenericRule>();
		for(GenericRule rule:rule_list){
			if(!rule.equals(sl.getTop())){
				if(rule.getAction()==FilteringAction.INCONSISTENT){
					
					Collection<GenericRule> rule_collection = new HashSet<GenericRule>();
					
					for(GenericRule r:sl.getOutgoingAdjacentVertices(rule)){
						if(!r.equals(sl.getTop()))
							rule_collection.add(r);
					}
					
					if(!can.getRuleClassifier().isHidden(rule,(GenericRule[])rule_collection.toArray()))
						rule_set.add(rule);
					else{
						//rule.setAction(FilteringAction.HIDDEN_INCONSISTENT);
						rule_set.addAll(getMinInconsistentRec(sl.getOutgoingAdjacentVertices(rule), sl));
					}
				} else {
					rule_set.addAll(getMinInconsistentRec(sl.getOutgoingAdjacentVertices(rule), sl));
				}
			}
		}
		return rule_set;
	}
	
}

