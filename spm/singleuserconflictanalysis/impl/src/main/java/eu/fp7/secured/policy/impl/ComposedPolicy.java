package eu.fp7.secured.policy.impl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.swing.plaf.SliderUI;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotPointException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.IllegalParamException;
import eu.fp7.secured.exception.rule.OperationNotPermittedException;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ComposedResolutionStrategy;
import eu.fp7.secured.policy.utils.PolicyType;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;




/**
 * The class ComposedPolicy implements the interface Policy. 
 * Its main purpose is to contain a composed policy.
 *  
 * The class contains seven private member variables: 
 * policy_list
 * defaultAction
 * rules
 * resolutionStrategy
 * org_policy_list
 * sourceSubnet
 * destSubnet.
 */
public class ComposedPolicy implements Policy{
	
	/** The member variable policy_list is a list of lists of policies which describes the structure of the composed policies. */
	private LinkedList<LinkedList<Policy>> policy_list;
	
	/** The member variable defaultAction contains the default action for the composed policy. */
	private Action defaultAction;
	
	/** The member variable rules is a set of all rules in the composed policy. */
	private HashSet<GenericRule> rules;
	
	/** The member variable resolutionStrategy contains the resolution strategy for the composed policy. */
	private GenericConflictResolutionStrategy resolutionStrategy;
	
	/** The member variable org_policy_list is a list of all original policies from which the composed policy is composed. */
	private List<Policy> org_policy_list;
	
	/** The member variable sourceSubnet contains all subnets from which a package can origin for this policy. */
	private GenericRule sourceSubnet=null;
	
	/** The member variable destSubnet contains all subnets to whom a package can be send. */
	private GenericRule destSubnet=null;
	
	private String name;
	
	private HashSet<String> selectorNames;
	
	private PolicyType policyType;
	
	/**
	 * The constructor instantiates a new composed policy, it accepts a list of lists of policies  
	 * and initializes the member variables. The member variable org_policy_list contains only one 
	 * instance of policy even if a composed policy contains multiple times one policy. To assure this 
	 * property this function before adding a policy to the list it checks that it is not already 
	 * in the list. 
	 * @param policy_list the policy_list
	 * @throws Exception the exception
	 */
	public ComposedPolicy(LinkedList<LinkedList<Policy>> policy_list, PolicyType policyType, String name) throws Exception{
		this.name = name;
		this.policy_list = policy_list;
		this.selectorNames = new HashSet<String>();
		this.rules = new HashSet<GenericRule>();
		org_policy_list = new LinkedList<Policy>();
		
		for(LinkedList<Policy> p_list:this.policy_list){
			for(Policy p:p_list)
				if(!org_policy_list.contains(p)){
					org_policy_list.add(p);
					this.selectorNames.addAll(p.getSelectorNames());
					rules.addAll(p.getRuleSet());
				}
		}
		
		
		this.resolutionStrategy = new ComposedResolutionStrategy(policy_list, org_policy_list);
		this.defaultAction = ((ComposedResolutionStrategy)this.resolutionStrategy).getDefaultAction();
		this.policyType = policyType;
	}


	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#clearRules()
	 */
	@Override
	public void clearRules() throws OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for ComposedPolicy Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#containsRule(org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public boolean containsRule(GenericRule rule) {
		return rules.contains(rule);
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
	public Set<GenericRule> getRuleSet() {
		return rules;
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertAll(java.util.Collection)
	 */
	@Override
	public void insertAll(Collection<GenericRule> rules)
			throws NoExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertAll(java.util.HashMap)
	 */
	@Override
	public <S> void insertAll(HashMap<GenericRule, S> rules)
			throws NoExternalDataException, IncompatibleExternalDataException,
			DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertRule(org.polito.ruleManagement.generalized.GenericRule)
	 */
	@Override
	public void insertRule(GenericRule rule) throws NoExternalDataException,
			OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#insertRule(org.polito.ruleManagement.generalized.GenericRule, java.lang.Object)
	 */
	@Override
	public <S> void insertRule(GenericRule rule, S externalData)
			throws IncompatibleExternalDataException,
			DuplicateExternalDataException, OperationNotPermittedException {
		throw new OperationNotPermittedException("Not allowed for Canonical Form Instance");
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	@Override
	public Policy clone(){
		ComposedPolicy result = null;
		try {
			result =  new ComposedPolicy(this.policy_list, this.policyType, this.name);
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
		rules.remove(rule);
	}

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#size()
	 */
	@Override
	public int size(){
		return rules.size();
	}

	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString(){
		String s="";
		
		for(LinkedList<Policy> p_list:policy_list){
			s=s+"( ";
			for(Policy p:p_list){
				s=s+p.hashCode()+" ";
			}
			
			s=s+") ";
		}
		return s;
	}

	/**
	 * The function getOriginalPolicy() returns the list of policies of witch the composed policy 
	 * is composed.
	 *
	 * @return the original policy
	 */
	public List<Policy> getOriginalPolicy() {
		return org_policy_list;
	}

	
	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#evalAction(org.polito.ruleManagement.generalized.ConditionClause)
	 */
	@Override
	public Action evalAction(ConditionClause c) throws NotPointException, SecurityException, IllegalArgumentException, IllegalParamException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException, NoExternalDataException, InvalidActionException{
	
		if (!c.isPoint(selectorNames))
			throw new NotPointException();
		
		HashSet<GenericRule> ruleSet = match(c);
		
		return resolutionStrategy.composeActions(ruleSet.toArray(new GenericRule[ruleSet.size()]));
	}
	

	/* (non-Javadoc)
	 * @see org.polito.policyManagement.policy.Policy#match(org.polito.ruleManagement.generalized.ConditionClause)
	 */
	@Override
	public HashSet<GenericRule> match(ConditionClause c) throws NotPointException, SecurityException, IllegalArgumentException, IllegalParamException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException{

		
		if (!c.isPoint(selectorNames))
			throw new NotPointException();
		
		HashSet<GenericRule> ruleSet = new HashSet<GenericRule>();
		for(GenericRule r : rules){
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
	public LinkedList<LinkedList<Policy>> getPolicyList() {
		return policy_list;
	}

	/**
	 * The function setSourceSubnet() is the setter function for the member variable sourceSubnet.
	 *
	 * @param sourceSubnet the new source subnet
	 */
	public void setSourceSubnet(GenericRule sourceSubnet) {
		this.sourceSubnet = sourceSubnet;
	}
	
	/**
	 * The function getSourceSubnet() is the getter function for the member variable sourceSubnet.
	 *
	 * @return the source subnet
	 */
	public GenericRule getSourceSubnet() {
		return sourceSubnet;
	}

	/**
	 * The function setDestSubnet() is the setter function for the member variable destSubnet.
	 *
	 * @param destSubnet the new dest subnet
	 */
	public void setDestSubnet(GenericRule destSubnet) {
		this.destSubnet = destSubnet;
	}

	/**
	 * The function getdestSubnet() is the getter function for the member variable destSubnet.
	 *
	 * @return the dest subnet
	 */
	public GenericRule getDestSubnet() {
		return destSubnet;
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
			p = new ComposedPolicy(policy_list, policyType, name);
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


