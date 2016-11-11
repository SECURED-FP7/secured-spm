package eu.fp7.secured.policy.impl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
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
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ApacheOrderAllowDenyResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ApacheOrderDenyAllowResolutionStrategy;
import eu.fp7.secured.policy.utils.BlockList;
import eu.fp7.secured.policy.utils.PointList;
import eu.fp7.secured.policy.utils.PolicyType;
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

public class PolicyImpl implements Policy {
	
	private final Logger LOGGER = Logger.getLogger(RuleClassifier.class.getName());

	private GenericConflictResolutionStrategy resolutionStrategy;
	private Action defaultAction;
	private LinkedHashSet<GenericRule> rules;
	private String name;
	private boolean usesExternalData = false;
	private HashSet<String> selectorNames;
	private RuleClassifier ruleClassifier;
	private PolicyType policyType;

	public PolicyImpl(GenericConflictResolutionStrategy resolutionStrategy, Action defaultAction, PolicyType policyType, String name) {
		this.name = name;
		this.defaultAction = defaultAction;
		// Valutare se mantenere Clone
		this.resolutionStrategy = resolutionStrategy.cloneResolutionStrategy();
		this.rules = new LinkedHashSet<GenericRule>();
		this.selectorNames = new HashSet<String>();
		this.policyType = policyType;

		if (resolutionStrategy instanceof ExternalDataResolutionStrategy)
			usesExternalData = true;

		if (resolutionStrategy instanceof ApacheOrderDenyAllowResolutionStrategy && defaultAction != FilteringAction.DENY || resolutionStrategy instanceof ApacheOrderAllowDenyResolutionStrategy && defaultAction != FilteringAction.ALLOW)
			System.err.println("The policy is correct, however it is not a valid Apache Policy.\n The default action is not DENY.");
		ruleClassifier = new RuleClassifier(this);
	}

	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException, UnsupportedSelectorException {
		if (usesExternalData)
			throw new NoExternalDataException();
		
		insert(rule);
	}
	
	public RuleClassifier getRuleClassifier(){
		return ruleClassifier;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <S> void insertRule(GenericRule rule, S externalData) throws IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException {
		if (!usesExternalData)
			throw new IncompatibleExternalDataException();

		((ExternalDataResolutionStrategy<GenericRule, S>) resolutionStrategy).setExternalData(rule, externalData);
		
		insert(rule);
	}

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
	
	@Override
	public void insertAll(Collection<GenericRule> rules) throws NoExternalDataException {
		if (usesExternalData)
			throw new NoExternalDataException();

		this.rules.addAll(rules);
		for (GenericRule rule : rules) {
			selectorNames.addAll(rule.getConditionClause().getSelectorsNames());
		}
	}

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

	@Override
	public boolean containsRule(GenericRule rule) {
		return rules.contains(rule);
	}

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

	/**
	 * @return the defaultAction
	 */
	@Override
	public Action getDefaultAction() {
		return defaultAction;
	}

	/**
	 * @return the resolutionStrategy
	 */
	@Override
	public GenericConflictResolutionStrategy getResolutionStrategy() {
		return resolutionStrategy;
	}

	/**
	 * @return the rules
	 */
	@Override
	public Set<GenericRule> getRuleSet() {
		return rules;
	}

	@Override
	public int size() {
		return rules.size();
	}

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

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public HashSet<String> getSelectorNames() {
		return selectorNames;
	}

	@Override
	public Policy policyClone() {
		Policy p = null;
		try {
			p = new PolicyImpl(resolutionStrategy.cloneResolutionStrategy(), defaultAction, policyType, name);
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

	@Override
	public PolicyType getPolicyType() {
		return this.policyType;
	}

}