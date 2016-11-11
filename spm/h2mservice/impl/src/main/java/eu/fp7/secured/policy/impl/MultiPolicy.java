package eu.fp7.secured.policy.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotPointException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.OperationNotPermittedException;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.MultiTypeResolutionStrategy;
import eu.fp7.secured.policy.utils.PolicyType;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;


public class MultiPolicy implements Policy {

	/** The member variable policy_list is a list of lists of policies which describes the structure of the composed policies. */
	private LinkedList<Policy> policy_list;
	
	/** The member variable defaultAction contains the default action for the composed policy. */
	private Action defaultAction;
	
	private String name;
	
	private HashSet<String> selectorNames;
	
	private PolicyType policyType;
	
	/** The member variable resolutionStrategy contains the resolution strategy for the composed policy. */
	private GenericConflictResolutionStrategy resolutionStrategy;

	
	/**
	 * The constructor instantiates a new composed policy, it accepts a list of lists of policies  
	 * and initializes the member variables. The member variable org_policy_list contains only one 
	 * instance of policy even if a composed policy contains multiple times one policy. To assure this 
	 * property this function before adding a policy to the list it checks that it is not already 
	 * in the list. 
	 * @param policy_list the policy_list
	 * @throws Exception the exception
	 */
	public MultiPolicy(LinkedList<Policy> policy_list, Action defaultAction, PolicyType policyType, String name) throws Exception{
		this.name = name;
		this.policy_list = policy_list;
		this.selectorNames = new HashSet<String>();
		for(Policy p:policy_list)
			this.selectorNames.addAll(p.getSelectorNames());
		this.resolutionStrategy = new MultiTypeResolutionStrategy(policy_list, defaultAction);
		this.defaultAction = defaultAction;
		this.policyType = policyType;
	}



	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#clearRules()
	 */
	@Override
	public void clearRules() throws OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for MultiPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#containsRule(org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public boolean containsRule(GenericRule rule) {
		
		boolean found = false;
		
		for (Policy p:policy_list){
			if(p.getRuleSet().contains(rule))
				found=true;
		}
		return found;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#getDefaultAction()
	 */
	@Override
	public Action getDefaultAction() {
		return defaultAction;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#getResolutionStrategy()
	 */
	@Override
	public GenericConflictResolutionStrategy getResolutionStrategy() {
		return resolutionStrategy;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#getRuleSet()
	 */
	@Override
	public Set<GenericRule> getRuleSet()  {
		HashSet<GenericRule> rules = new HashSet<GenericRule>();
		
		for(Policy p:policy_list)
				rules.addAll(p.getRuleSet());
		
		return rules;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertAll(java.util.Collection)
	 */
	@Override
	public void insertAll(Collection<GenericRule> rules)
			throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for MultiPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertAll(java.util.HashMap)
	 */
	@Override
	public <S> void insertAll(HashMap<GenericRule, S> rules)
			throws NoExternalDataException, IncompatibleExternalDataException,
			DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for MultiPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertRule(org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException,
			OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for MultiPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertRule(org.polito.ruleManagement.generalized.GenericRule, java.lang.Object)
	 */
	@Override
	public <S> void insertRule(GenericRule rule, S externalData)
			throws IncompatibleExternalDataException,
			DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for MultiPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	@Override
	public Policy clone(){
		MultiPolicy result = null;
		try {
			result =  new MultiPolicy(this.policy_list, this.defaultAction, this.policyType, this.name);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#removeAll(java.util.Collection)
	 */
	@Override
	public void removeAll(Collection<GenericRule> rules)
			throws UnmanagedRuleException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}



	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#removeRule(org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public void removeRule(GenericRule rule) throws UnmanagedRuleException,
			OperationNotPermittedException {
		for(Policy p:policy_list){
			if(p.containsRule(rule))
				p.removeRule(rule);
		}
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#size()
	 */
	@Override
	public int size(){
		return getRuleSet().size();
	}

	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString(){
		String s="";
		
		for(Policy p:policy_list){
				s=s+p.hashCode()+" ";
			
		}
		
		s=s+"/n";
		
		for(Policy p:policy_list){
			s=s+p.getRuleSet()+" ";
		
		}
		
		return s;
	}

	
	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#evalAction(org.polito.ruleManagement.generalized.ConditionClause)
	 */
	@Override
	public Action evalAction(ConditionClause c) throws Exception{
	
		if (!c.isPoint(selectorNames))
			throw new NotPointException();
		
		HashSet<GenericRule> ruleSet = match(c);
		
		return resolutionStrategy.composeActions(ruleSet.toArray(new GenericRule[ruleSet.size()]));
	}
	

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#match(org.polito.ruleManagement.generalized.ConditionClause)
	 */
	@Override
	public HashSet<GenericRule> match(ConditionClause c) throws Exception{
		
		if (!c.isPoint(selectorNames))
			throw new NotPointException();
		
		HashSet<GenericRule> ruleSet = new HashSet<GenericRule>();
		for(GenericRule r : getRuleSet()){
			if(r.isIntersecting(c)){
				ruleSet.add(r);
			}
		}
			
		return ruleSet;
	}

	/**
	 * The function getPolicyList() is the getter function for the member variable policy_list.
	 *
	 * @return the policy list
	 */
	public LinkedList<Policy> getPolicyList() {
		return policy_list;
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
			p = new MultiPolicy(policy_list, defaultAction, policyType, name);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return p;
	}



	@Override
	public RuleClassifier getRuleClassifier() {
		// TODO Auto-generated method stub
		return null;
	}



	@Override
	public PolicyType getPolicyType() {
		return policyType;
	}




}
