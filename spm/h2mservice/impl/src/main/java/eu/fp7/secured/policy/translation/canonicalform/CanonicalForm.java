package eu.fp7.secured.policy.translation.canonicalform;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
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
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.translation.semilattice.Semilattice;
import eu.fp7.secured.policy.utils.BlockList;
import eu.fp7.secured.policy.utils.IndexingBitSet;
import eu.fp7.secured.policy.utils.PointList;
import eu.fp7.secured.policy.utils.PolicyType;
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


public class CanonicalForm implements Policy {

	private Policy policy;

	private Set<GenericRule> canRules;
	
	private HashMap<GenericRule, IndexingBitSet> canLabels;
	private HashMap<IndexingBitSet, GenericRule> ibsLabel;
	
	private Semilattice<GenericRule> semiLattice;
	
	private SelectorTypes selectorTypes;
	
	private PolicyType policyType;
	
	private RuleClassifier ruleClassifier;
	
	private HashSet<String> selectorNames;

	public CanonicalForm(Policy policy, SelectorTypes selectorTypes) {

		this.policy=policy;
		this.selectorTypes = selectorTypes;
		this.policyType = PolicyType.FILTERING;
		
		this.selectorNames = new HashSet<>();

		canRules = null;
		
		semiLattice = null;
	}
	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public <S> void insertRule(GenericRule rule, S externalData)
	throws IncompatibleExternalDataException,
	DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public void insertAll(Collection<GenericRule> rules)
	throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public <S> void insertAll(HashMap<GenericRule, S> rules)
	throws NoExternalDataException, IncompatibleExternalDataException,
	DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public void removeRule(GenericRule rule) throws UnmanagedRuleException,
	OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public void removeAll(Collection<GenericRule> rules)
	throws UnmanagedRuleException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public boolean containsRule(GenericRule rule) {
		return canRules.contains(rule);
	}

	@Override
	public void clearRules() throws OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	@Override
	public Action getDefaultAction() {
		return policy.getDefaultAction();
	}

	@Override
	public GenericConflictResolutionStrategy getResolutionStrategy() {
		return policy.getResolutionStrategy();
	}

	@Override
	public Set<GenericRule> getRuleSet() {
		return canRules; 
	}

	@Override
	public int size(){
		return canRules.size();
	}


	@Override
	public Policy clone() {
		return null;
	}
	

	
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

	public GenericRule[] getOriginalRules(GenericRule rule) {
		GenericRule[] rules1 = CanonicalFormGenerator.getInstance(policy, selectorTypes).decomposeRule(rule, this);
		GenericRule[] rules = new GenericRule[rules1.length-1];
		for(int i=0; i<rules1.length-1; i++)
			rules[i]=rules1[i];
		return rules;
	}

	
	public void setSemiLattice(Semilattice<GenericRule> semiLattice){
		
		this.semiLattice = semiLattice;
	}
	
	public void setRules(Set<GenericRule> rules) {
		canRules = rules;
	}
	
	public Semilattice<GenericRule> getSemiLattice() throws Exception {
		return semiLattice;
	}

	public HashMap<GenericRule, IndexingBitSet> getLabels() throws UnsupportedSelectorException, UnmanagedRuleException, ResolutionErrorException, NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException {
		return canLabels;
	}
	
	public void setLabels(HashMap<GenericRule, IndexingBitSet> canLabels) {
		this.canLabels = canLabels;
	}
	
	public void setIbsLabels(HashMap<IndexingBitSet, GenericRule> ibsLabel) {
		this.ibsLabel = ibsLabel;
	}
	public Policy getOriginalPolicy() {
		return policy;
	}
	@Override
	public String getName() {
		return "CAN_"+policy.getName();
	}
	@Override
	public HashSet<String> getSelectorNames() {
		return policy.getSelectorNames();
	}
	@Override
	public Policy policyClone() {
		return null;
	}
	@Override
	public PolicyType getPolicyType() {
		return policyType;
	}
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

}
