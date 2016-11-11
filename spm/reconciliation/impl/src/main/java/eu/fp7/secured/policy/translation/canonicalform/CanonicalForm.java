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
package eu.fp7.secured.policy.translation.canonicalform;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotPointException;
import eu.fp7.secured.exception.policy.ResolutionErrorException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.OperationNotPermittedException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.translation.semilattice.Semilattice;
import eu.fp7.secured.policy.utils.BlockList;
import eu.fp7.secured.policy.utils.IndexingBitSet;
import eu.fp7.secured.policy.utils.PointList;
import eu.fp7.secured.policy.utils.RegexBlockList;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.rule.selector.TotalOrderedSelector;
import eu.fp7.secured.selector.impl.RateLimitSelector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;


/**
 * The Class CanonicalForm.
 */
public class CanonicalForm implements Policy {

	/** The policy. */
	private Policy policy;

	/** The can rules. */
	private Set<GenericRule> canRules;
	
	/** The can labels. */
	private HashMap<GenericRule, IndexingBitSet> canLabels;
	
	/** The ibs label. */
	private HashMap<IndexingBitSet, GenericRule> ibsLabel;
	
	/** The semi lattice. */
	private Semilattice<GenericRule> semiLattice;
	
	/** The selector types. */
	private SelectorTypes selectorTypes;
	
	/** The capability. */
	private LinkedList<Capability> capability;
	
	/** The rule classifier. */
	private RuleClassifier ruleClassifier;
	
	/** The selector names. */
	private HashSet<String> selectorNames;

	/**
	 * Instantiates a new canonical form.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 */
	public CanonicalForm(Policy policy, SelectorTypes selectorTypes) {

		this.policy=policy;
		this.selectorTypes = selectorTypes;
		this.capability = new LinkedList<>();
		
		this.selectorNames = new HashSet<>();

		canRules = null;
		
		semiLattice = null;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertRule(eu.fp7.secured.rule.impl.GenericRule, java.lang.Object)
	 */
	@Override
	public <S> void insertRule(GenericRule rule, S externalData)
	throws IncompatibleExternalDataException,
	DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertAll(java.util.Collection)
	 */
	@Override
	public void insertAll(Collection<GenericRule> rules)
	throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertAll(java.util.HashMap)
	 */
	@Override
	public <S> void insertAll(HashMap<GenericRule, S> rules)
	throws NoExternalDataException, IncompatibleExternalDataException,
	DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#removeRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public void removeRule(GenericRule rule) throws UnmanagedRuleException,
	OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#removeAll(java.util.Collection)
	 */
	@Override
	public void removeAll(Collection<GenericRule> rules)
	throws UnmanagedRuleException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#containsRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public boolean containsRule(GenericRule rule) {
		return canRules.contains(rule);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#clearRules()
	 */
	@Override
	public void clearRules() throws OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getDefaultAction()
	 */
	@Override
	public Action getDefaultAction() {
		return policy.getDefaultAction();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getResolutionStrategy()
	 */
	@Override
	public GenericConflictResolutionStrategy getResolutionStrategy() {
		return policy.getResolutionStrategy();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getRuleSet()
	 */
	@Override
	public Set<GenericRule> getRuleSet() {
		return canRules; 
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#size()
	 */
	@Override
	public int size(){
		return canRules.size();
	}


	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	@Override
	public Policy clone() {
		return null;
	}
	

	
	/**
	 * Find lub rule.
	 *
	 * @param c the c
	 * @return the generic rule
	 * @throws Exception the exception
	 */
	private GenericRule findLUBRule(ConditionClause c) throws Exception {
		
		Semilattice<GenericRule> sl = semiLattice;
		
		GenericRule ret=sl.getRoot();
		
		boolean go=true;

		while (go){
			go=false;
			for(GenericRule r:sl.getOutgoingAdjacentVertices(ret)){
				if (r.isIntersecting(c)){
					ret=r;
					go=true;
					continue;
				}
			}
		}

		if (ret == sl.getRoot())
			return null;
		else return ret;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#match(eu.fp7.secured.rule.impl.ConditionClause)
	 */
	@Override
	public HashSet<GenericRule> match(ConditionClause c) throws Exception {
		
		if (!c.isPoint(policy.getSelectorNames()))
			throw new NotPointException();
		
		GenericRule lub = findLUBRule(c);

		HashSet<GenericRule> matchingRules = new HashSet<GenericRule>();
		
		if(lub!=null){
			
			matchingRules.add(lub);
			
			IndexingBitSet ibsLUB = canLabels.get(lub);
			
			for (IndexingBitSet ibs : ibsLabel.keySet())
				if (ibsLUB.hasAtLeastTheSameBitsAs(ibs))
					matchingRules.add(ibsLabel.get(ibs));
			
		}
		return matchingRules;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#evalAction(eu.fp7.secured.rule.impl.ConditionClause)
	 */
	@Override
	public Action evalAction(ConditionClause c) throws Exception {
		if (!c.isPoint(policy.getSelectorNames()))
			throw new NotPointException();

		GenericRule lub = findLUBRule(c);
		
		if(lub!=null)
			return lub.getAction();
		else
			return this.getDefaultAction();
	}

	/**
	 * Gets the original rules.
	 *
	 * @param rule the rule
	 * @return the original rules
	 */
	public GenericRule[] getOriginalRules(GenericRule rule) {
		GenericRule[] rules1 = CanonicalFormGenerator.getInstance(policy, selectorTypes).decomposeRule(rule, this);
		GenericRule[] rules = new GenericRule[rules1.length-1];
		for(int i=0; i<rules1.length-1; i++)
			rules[i]=rules1[i];
		return rules;
	}

	
	/**
	 * Sets the semi lattice.
	 *
	 * @param semiLattice the new semi lattice
	 */
	public void setSemiLattice(Semilattice<GenericRule> semiLattice){
		
		this.semiLattice = semiLattice;
	}
	
	/**
	 * Sets the rules.
	 *
	 * @param rules the new rules
	 */
	public void setRules(Set<GenericRule> rules) {
		canRules = rules;
	}
	
	/**
	 * Gets the semi lattice.
	 *
	 * @return the semi lattice
	 * @throws Exception the exception
	 */
	public Semilattice<GenericRule> getSemiLattice() throws Exception {
		return semiLattice;
	}

	/**
	 * Gets the labels.
	 *
	 * @return the labels
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws ResolutionErrorException the resolution error exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public HashMap<GenericRule, IndexingBitSet> getLabels() throws UnsupportedSelectorException, UnmanagedRuleException, ResolutionErrorException, NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException {
		return canLabels;
	}
	
	/**
	 * Sets the labels.
	 *
	 * @param canLabels the can labels
	 */
	public void setLabels(HashMap<GenericRule, IndexingBitSet> canLabels) {
		this.canLabels = canLabels;
	}
	
	/**
	 * Sets the ibs labels.
	 *
	 * @param ibsLabel the ibs label
	 */
	public void setIbsLabels(HashMap<IndexingBitSet, GenericRule> ibsLabel) {
		this.ibsLabel = ibsLabel;
	}
	
	/**
	 * Gets the original policy.
	 *
	 * @return the original policy
	 */
	public Policy getOriginalPolicy() {
		return policy;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getName()
	 */
	@Override
	public String getName() {
		return "CAN_"+policy.getName();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getSelectorNames()
	 */
	@Override
	public HashSet<String> getSelectorNames() {
		return policy.getSelectorNames();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#policyClone()
	 */
	@Override
	public Policy policyClone() {
		return null;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getCapability()
	 */
	@Override
	public LinkedList<Capability> getCapability() {
		return capability;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getRuleClassifier()
	 */
	@Override
	public RuleClassifier getRuleClassifier() {
		
		if (ruleClassifier!=null){
			return ruleClassifier;
		}
		
		ruleClassifier = new RuleClassifier(this);
		
		for(GenericRule rule:canRules){
		
		for(String sn:rule.getConditionClause().getSelectorsNames()){
			if(!selectorNames.contains(sn)){
				selectorNames.add(sn);
				BlockList blockList = null;
				Selector s = rule.getConditionClause().get(sn).selectorClone();
				s.full();
				if(s instanceof ExactMatchSelector || s instanceof TotalOrderedSelector || s instanceof RateLimitSelector){
					try {
						blockList = new PointList(s, sn);
					} catch (Exception e) {
						e.printStackTrace();
					} 
				}
				
				if(s instanceof RegExpSelector || s instanceof StandardRegExpSelector){
					try {
						blockList = new RegexBlockList((RegExpSelector)s);
					} catch (Exception e) {
						e.printStackTrace();
					} 
				}
				try {
					ruleClassifier.addSelector(sn, blockList);
				} catch (UnsupportedSelectorException e) {
					e.printStackTrace();
				}
			}
		}
		
		
		try {
			ruleClassifier.addRule(rule);
		} catch (UnsupportedSelectorException e) {
			e.printStackTrace();
		}
		}
		return ruleClassifier;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getCreator()
	 */
	@Override
	public String getCreator() {
		return "CANONICAL FORM";
	}

}
