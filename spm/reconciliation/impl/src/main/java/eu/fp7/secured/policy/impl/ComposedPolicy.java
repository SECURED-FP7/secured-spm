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
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.ComposedResolutionStrategy;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;




/**
 * The Class ComposedPolicy.
 */
public class ComposedPolicy implements Policy{
	
	/** The policy_list. */
	private LinkedList<LinkedList<Policy>> policy_list;
	
	/** The default action. */
	private Action defaultAction;
	
	/** The rules. */
	private HashSet<GenericRule> rules;
	
	/** The resolution strategy. */
	private GenericConflictResolutionStrategy resolutionStrategy;
	
	/** The org_policy_list. */
	private List<Policy> org_policy_list;
	
	/** The source subnet. */
	private GenericRule sourceSubnet=null;
	
	/** The dest subnet. */
	private GenericRule destSubnet=null;
	
	/** The name. */
	private String name;
	
	/** The creator. */
	private String creator;
	
	/** The selector names. */
	private HashSet<String> selectorNames;
	
	/** The capability. */
	private LinkedList<Capability> capability;
	
	/**
	 * Instantiates a new composed policy.
	 *
	 * @param policy_list the policy_list
	 * @param capability the capability
	 * @param name the name
	 * @param creator the creator
	 * @throws Exception the exception
	 */
	public ComposedPolicy(LinkedList<LinkedList<Policy>> policy_list, LinkedList<Capability> capability, String name, String creator) throws Exception{
		this.name = name;
		this.creator = creator;
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
		this.capability = capability;
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
			result =  new ComposedPolicy(this.policy_list, this.capability, this.name, this.creator);
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
	 * Gets the original policy.
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
	 * Gets the policy list.
	 *
	 * @return the policy list
	 */
	public LinkedList<LinkedList<Policy>> getPolicyList() {
		return policy_list;
	}

	/**
	 * Sets the source subnet.
	 *
	 * @param sourceSubnet the new source subnet
	 */
	public void setSourceSubnet(GenericRule sourceSubnet) {
		this.sourceSubnet = sourceSubnet;
	}
	
	/**
	 * Gets the source subnet.
	 *
	 * @return the source subnet
	 */
	public GenericRule getSourceSubnet() {
		return sourceSubnet;
	}

	/**
	 * Sets the dest subnet.
	 *
	 * @param destSubnet the new dest subnet
	 */
	public void setDestSubnet(GenericRule destSubnet) {
		this.destSubnet = destSubnet;
	}

	/**
	 * Gets the dest subnet.
	 *
	 * @return the dest subnet
	 */
	public GenericRule getDestSubnet() {
		return destSubnet;
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
			p = new ComposedPolicy(policy_list, capability, name, creator);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return p;
	}


	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.impl.Policy#getRuleClassifier()
	 */
	@Override
	public RuleClassifier getRuleClassifier() {
		// TODO Auto-generated method stub
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
	 * @see eu.fp7.secured.policy.impl.Policy#getCreator()
	 */
	@Override
	public String getCreator() {
		return creator;
	}

}


