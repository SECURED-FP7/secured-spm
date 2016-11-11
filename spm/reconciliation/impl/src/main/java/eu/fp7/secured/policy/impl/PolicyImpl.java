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
package eu.fp7.secured.policy.impl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.EmptySelectorException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotPointException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.IllegalParamException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ApacheOrderAllowDenyResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ApacheOrderDenyAllowResolutionStrategy;
import eu.fp7.secured.policy.utils.BlockList;
import eu.fp7.secured.policy.utils.PointList;
import eu.fp7.secured.policy.utils.RegexBlockList;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.rule.selector.TotalOrderedSelector;
import eu.fp7.secured.selector.impl.RateLimitSelector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;

/**
 * The Class PolicyImpl.
 */
public class PolicyImpl implements Policy {
	
	/** The logger. */
	private final Logger LOGGER = Logger.getLogger(RuleClassifier.class.getName());

	/** The resolution strategy. */
	private GenericConflictResolutionStrategy resolutionStrategy;
	
	/** The default action. */
	private Action defaultAction;
	
	/** The rules. */
	private LinkedHashSet<GenericRule> rules;
	
	/** The name. */
	private String name;
	
	/** The creator. */
	private String creator;
	
	/** The uses external data. */
	private boolean usesExternalData = false;
	
	/** The selector names. */
	private HashSet<String> selectorNames;
	
	/** The rule classifier. */
	private RuleClassifier ruleClassifier;
	
	/** The capability. */
	private List<Capability> capability;
	
	/**
	 * Instantiates a new policy impl.
	 *
	 * @param resolutionStrategy the resolution strategy
	 * @param defaultAction the default action
	 * @param capability the capability
	 * @param name the name
	 * @param creator the creator
	 */
	public PolicyImpl(GenericConflictResolutionStrategy resolutionStrategy, Action defaultAction, List<Capability> capability, String name, String creator) {
		this.name = name;
		this.creator = creator;
		this.defaultAction = defaultAction;
		// Valutare se mantenere Clone
		this.resolutionStrategy = resolutionStrategy.cloneResolutionStrategy();
		this.rules = new LinkedHashSet<GenericRule>();
		this.selectorNames = new HashSet<String>();
		this.capability = capability;

		if (resolutionStrategy instanceof ExternalDataResolutionStrategy)
			usesExternalData = true;

		if (resolutionStrategy instanceof ApacheOrderDenyAllowResolutionStrategy && defaultAction != FilteringAction.DENY || resolutionStrategy instanceof ApacheOrderAllowDenyResolutionStrategy && defaultAction != FilteringAction.ALLOW)
			System.err.println("The policy is correct, however it is not a valid Apache Policy.\n The default action is not DENY.");
		ruleClassifier = new RuleClassifier(this);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException, UnsupportedSelectorException {
		if (usesExternalData)
			throw new NoExternalDataException();
		
		insert(rule);
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getRuleClassifier()
	 */
	public RuleClassifier getRuleClassifier(){
		return ruleClassifier;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertRule(eu.fp7.secured.rule.impl.GenericRule, java.lang.Object)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public <S> void insertRule(GenericRule rule, S externalData) throws IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException {
		if (!usesExternalData)
			throw new IncompatibleExternalDataException();

		((ExternalDataResolutionStrategy<GenericRule, S>) resolutionStrategy).setExternalData(rule, externalData);
		
		insert(rule);
	}

	/**
	 * Insert.
	 *
	 * @param rule the rule
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	private void insert(GenericRule rule) throws UnsupportedSelectorException{
		rules.add(rule);
		
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
				if(blockList == null){
					LOGGER.severe(sn);
				}
				ruleClassifier.addSelector(sn, blockList);
			}
		}
		
		
		try {
			ruleClassifier.addRule(rule);
		} catch (UnsupportedSelectorException e) {
			e.printStackTrace();
		}
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertAll(java.util.Collection)
	 */
	@Override
	public void insertAll(Collection<GenericRule> rules) throws NoExternalDataException {
		if (usesExternalData)
			throw new NoExternalDataException();

		this.rules.addAll(rules);
		for (GenericRule rule : rules) {
			selectorNames.addAll(rule.getConditionClause().getSelectorsNames());
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#insertAll(java.util.HashMap)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public <S> void insertAll(HashMap<GenericRule, S> rules) throws NoExternalDataException, IncompatibleExternalDataException, DuplicateExternalDataException {
		if (!usesExternalData)
			throw new IncompatibleExternalDataException();

		// Come verificare che S sia compatibile?
		for (GenericRule r : rules.keySet())
			((ExternalDataResolutionStrategy<GenericRule, S>) resolutionStrategy).setExternalData(r, rules.get(r));

		this.rules.addAll(rules.keySet());
		for (GenericRule rule : rules.keySet()) {
			selectorNames.addAll(rule.getConditionClause().getSelectorsNames());
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#removeRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void removeRule(GenericRule rule) throws UnmanagedRuleException {
		if (usesExternalData)
			((ExternalDataResolutionStrategy<GenericRule, Object>) resolutionStrategy).clearExternalData(rule);

		if (rules.contains(rule)) {
			rules.remove(rule);
		} else
			throw new UnmanagedRuleException();
		// System.err.println("Rule\n"+ rule + "not contained in the DB");

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#removeAll(java.util.Collection)
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void removeAll(Collection<GenericRule> rules) throws UnmanagedRuleException {
		this.rules.removeAll(rules);

		for (GenericRule rule : rules) {
			if (rules.contains(rule)) {
				// this.rules.remove(rule);
				if (usesExternalData)
					((ExternalDataResolutionStrategy<GenericRule, Object>) resolutionStrategy).clearExternalData(rule);

			} else
				throw new UnmanagedRuleException();
			// System.err.println("Rule\n"+ rule + "not contained in the DB");
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#containsRule(eu.fp7.secured.rule.impl.GenericRule)
	 */
	@Override
	public boolean containsRule(GenericRule rule) {
		return rules.contains(rule);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#clearRules()
	 */
	@Override
	@SuppressWarnings("unchecked")
	public void clearRules() {
		for (GenericRule rule : rules) {
			if (usesExternalData)
				((ExternalDataResolutionStrategy<GenericRule, Object>) resolutionStrategy).clearExternalData(rule);
		}

		rules.clear();
		// rules = new HashSet<GenericRule>();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getDefaultAction()
	 */
	@Override
	public Action getDefaultAction() {
		return defaultAction;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getResolutionStrategy()
	 */
	@Override
	public GenericConflictResolutionStrategy getResolutionStrategy() {
		return resolutionStrategy;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getRuleSet()
	 */
	@Override
	public Set<GenericRule> getRuleSet() {
		return rules;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#size()
	 */
	@Override
	public int size() {
		return rules.size();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@SuppressWarnings("unchecked")
	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("----BEGIN POLICY---------------------------------\n");
		buf.append("Resolution Strategy: " + resolutionStrategy + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Default Action: " + defaultAction + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Rules (Total " + rules.size() + "): \n");
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule, ?>) resolutionStrategy;
			for (GenericRule rule : rules) {
				buf.append(rule + "-->" + (ext.getExternalData(rule)) + "\n");
			}
		} else
			for (GenericRule rule : rules) {
				buf.append(rule);
			}
		buf.append("\n----END POLICY-----------------------------------\n");
		return buf.toString();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#evalAction(eu.fp7.secured.rule.impl.ConditionClause)
	 */
	@Override
	public Action evalAction(ConditionClause c) throws NotPointException, SecurityException, IllegalArgumentException, IllegalParamException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException, NoExternalDataException, InvalidActionException {

		if (!c.isPoint(selectorNames)) {
			throw new NotPointException();
		}

		HashSet<GenericRule> ruleSet = match(c);

		if (ruleSet.size() == 0)
			return defaultAction;

		return resolutionStrategy.composeActions(ruleSet.toArray(new GenericRule[ruleSet.size()]));
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#match(eu.fp7.secured.rule.impl.ConditionClause)
	 */
	@Override
	public HashSet<GenericRule> match(ConditionClause c) throws NotPointException, SecurityException, IllegalArgumentException, IllegalParamException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException {

		if (!c.isPoint(selectorNames))
			throw new NotPointException();

		HashSet<GenericRule> ruleSet = new HashSet<GenericRule>();
		for (GenericRule r : rules) {
			if (r.isIntersecting(c)) {
				ruleSet.add(r);
			}
		}

		return ruleSet;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getName()
	 */
	@Override
	public String getName() {
		return this.name;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getSelectorNames()
	 */
	@Override
	public HashSet<String> getSelectorNames() {
		return selectorNames;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#policyClone()
	 */
	@Override
	public Policy policyClone() {
		Policy p = null;
		try {
			p = new PolicyImpl(resolutionStrategy.cloneResolutionStrategy(), defaultAction, capability, name, creator);
			if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
				for (GenericRule rule : rules)
					p.insertRule(rule.ruleClone(), ((ExternalDataResolutionStrategy) resolutionStrategy).getExternalData(rule));
			} else {
				for (GenericRule rule : rules)
					p.insertRule(rule.ruleClone());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return p;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getCapability()
	 */
	@Override
	public List<Capability> getCapability() {
		return this.capability;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getCreator()
	 */
	@Override
	public String getCreator() {
		return creator;
	}

}