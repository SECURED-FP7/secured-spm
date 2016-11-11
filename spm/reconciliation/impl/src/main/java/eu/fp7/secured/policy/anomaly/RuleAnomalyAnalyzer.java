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
package eu.fp7.secured.policy.anomaly;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Class RuleAnomalyAnalyzer.
 */
public class RuleAnomalyAnalyzer {
	
	/** The policy. */
	private Policy  policy;
	
	/** The resolver. */
	private GenericConflictResolutionStrategy resolver;
	
	/** The rules. */
	private Set<GenericRule> rules;
	
	/** The default action. */
	private Action defaultAction;
	
	/** The selector types. */
	private SelectorTypes selectorTypes;
	
	//TODO: add contains check in every method
	
	/**
	 * Instantiates a new rule anomaly analyzer.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 */
	public RuleAnomalyAnalyzer(Policy policy, SelectorTypes selectorTypes) {
		this.policy = policy;
		this.resolver = policy.getResolutionStrategy();
		this.rules = policy.getRuleSet();
		this.defaultAction = policy.getDefaultAction();
		this.selectorTypes = selectorTypes;
	}
	
	/**
	 * Checks if is equivalent.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return true, if is equivalent
	 * @throws Exception the exception
	 */
	public boolean isEquivalent(GenericRule r1, GenericRule r2) throws Exception {
		if(!resolver.isActionEquivalent(r1, r2))
			return false;

		if(resolver.compare(r1, r2) != ResolutionComparison.EQUIVALENT)
			return false;
		
		if(!r1.isConditionEquivalent(r2))
			return false;

		
		return true;
	}
	
	/**
	 * Checks if is hidden or equivalent.
	 *
	 * @param hidden the hidden
	 * @param hider the hider
	 * @return true, if is hidden or equivalent
	 * @throws Exception the exception
	 */
	public boolean isHiddenOrEquivalent(GenericRule hidden, GenericRule hider) throws Exception {
		ResolutionComparison comp = resolver.compare(hidden, hider);
		if(comp == ResolutionComparison.UNIVERSALLY_GREATER)
			return false;
		if(!hidden.isConditionSubsetOrEquivalent(hider))
			return false;

		else if(!hidden.getAction().equals(hider.getAction()) && comp==ResolutionComparison.NON_UNIVERSALLY_COMPARABLE)
			throw new Exception("This scenario is not allowed by theory: indecidible conflict. " +
					"Incorrect resolution definition or implementation mistakes.");
		
		return true;

	}

	/**
	 * Checks if is hidden.
	 *
	 * @param hidden the hidden
	 * @param hider the hider
	 * @return true, if is hidden
	 * @throws Exception the exception
	 */
	public boolean isHidden(GenericRule hidden, GenericRule hider) throws Exception {		
		ResolutionComparison comp = resolver.compare(hidden, hider);
		if(comp == ResolutionComparison.UNIVERSALLY_GREATER)
			return false;
		if(!hidden.isConditionSubsetOrEquivalent(hider))
			return false;
		if(hidden.isConditionEquivalent(hider) && comp == ResolutionComparison.EQUIVALENT)
			return false;
		else if(!hidden.getAction().equals(hider.getAction()) && comp==ResolutionComparison.NON_UNIVERSALLY_COMPARABLE)
			throw new Exception("This scenario is not allowed by theory: indecidible conflict. " +
					"Incorrect resolution definition or implementation mistakes.");
		
		return true;
	}
	
	/**
	 * Checks if is redundant.
	 *
	 * @param redundant the redundant
	 * @param hider the hider
	 * @return true, if is redundant
	 * @throws Exception the exception
	 */
	public boolean isRedundant(GenericRule redundant, GenericRule hider) throws Exception{
		if(!hider.getAction().equals(redundant.getAction()))
			return false;
		
		return isHidden(redundant, hider);
	}
	
	/**
	 * Checks if is shadowed.
	 *
	 * @param shadowed the shadowed
	 * @param hider the hider
	 * @return true, if is shadowed
	 * @throws Exception the exception
	 */
	public boolean isShadowed(GenericRule shadowed, GenericRule hider) throws Exception
	{
		if(hider.getAction().equals(shadowed.getAction()))
			return false;
		
		return isHidden(shadowed, hider);
	}

	/**
	 * Checks if is greater.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return true, if is greater
	 * @throws Exception the exception
	 */
	public boolean isGreater(GenericRule r1, GenericRule r2) throws Exception {
		ResolutionComparison comp = resolver.compare(r1, r2);
		if(comp != ResolutionComparison.UNIVERSALLY_GREATER)
			return false;
		if(r1.isConditionSubset(r2))
			return false;
		
		return true;
		
	}

	/**
	 * Checks if is less.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return true, if is less
	 * @throws Exception the exception
	 */
	public boolean isLess(GenericRule r1, GenericRule r2) throws Exception {
		ResolutionComparison comp = resolver.compare(r1, r2);
		if(comp != ResolutionComparison.UNIVERSALLY_LESS)
			return false;

		if(r2.isConditionSubset(r1))
			return false;
		
		return true;
	}
	
	/**
	 * Checks if is general hidden.
	 *
	 * @param rule the rule
	 * @param hiderlist the hiderlist
	 * @return true, if is general hidden
	 * @throws Exception the exception
	 */
	public boolean isGeneralHidden(GenericRule rule, GenericRule[] hiderlist) throws Exception
	{
		return policy.getRuleClassifier().isHidden(rule, hiderlist);
	}
	
	/**
	 * Checks if is general unnecessary.
	 *
	 * @param rule the rule
	 * @param hiderlist the hiderlist
	 * @return true, if is general unnecessary
	 * @throws Exception the exception
	 */
	public boolean isGeneralUnnecessary(GenericRule rule, GenericRule[] hiderlist) throws Exception
	{
		return policy.getRuleClassifier().isUnnecessary(rule, hiderlist);		
	}
	
	/**
	 * Checks if is general redundant.
	 *
	 * @param rule the rule
	 * @param hiderlist the hiderlist
	 * @return true, if is general redundant
	 * @throws Exception the exception
	 */
	public boolean isGeneralRedundant(GenericRule rule, GenericRule[] hiderlist) throws Exception
	{
		Action a = rule.getAction();
		for(GenericRule r:hiderlist)
		{
			if(a != r.getAction()) return false;
		}
		
		return policy.getRuleClassifier().isHidden(rule, hiderlist);
		
	}
	
	/**
	 * Checks if is general shadowed.
	 *
	 * @param rule the rule
	 * @param hiderlist the hiderlist
	 * @return true, if is general shadowed
	 * @throws Exception the exception
	 */
	public boolean isGeneralShadowed(GenericRule rule, GenericRule[] hiderlist) throws Exception
	{
		Action a = rule.getAction();
		boolean found = false;
		for(GenericRule r:hiderlist)
		{
			if(a != r.getAction()) found = true;
		}
		if(!found) return false;
		
		
		return policy.getRuleClassifier().isHidden(rule, hiderlist);
		
	}

	/**
	 * Checks if is conflicting.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return true, if is conflicting
	 */
	public boolean isConflicting(GenericRule r1, GenericRule r2)
	{
			return r1.isIntersecting(r2) && !resolver.isActionEquivalent(r1, r2);
			
	}
	
	/**
	 * Gets the anomalies.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the anomalies
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	public ConflictType getAnomalies(GenericRule r1, GenericRule r2) throws UnmanagedRuleException{
		if(!(policy.containsRule(r1) || policy.containsRule(r2)))
			throw new UnmanagedRuleException();
		return private_classify(r1, r2);
	}
	
	/**
	 * Private_classify.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the conflict type
	 */
	/*
	 * private_classify
	 */
	private ConflictType private_classify(GenericRule r1, GenericRule r2){
		
		if(r1.equals(r2))
			return ConflictType.IDENTICAL;
		
		if(!r1.isIntersecting(r2)) 
			return ConflictType.NON_INTERSECTING;
		
		ResolutionComparison res;

		
			
			try {
				
				res = resolver.compare(r1, r2);
				
				if(res == ResolutionComparison.UNIVERSALLY_GREATER){ // greater (conf, non conf), hides(makes_red || shadows)
					if(r2.isConditionSubsetOrEquivalent(r1)){
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.MAKES_REDUNDANT;
						else
							return ConflictType.SHADOWS;
					}
					else if(r1.isConditionSubset(r2)){
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.GREATER_but_NOT_CONFLICTING;
						else
							return ConflictType.GREATER;
					}
					else{
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
						else
							return ConflictType.CONFLICTING;
					}
				}
				if(res == ResolutionComparison.UNIVERSALLY_LESS){ //less (conf , non conf), ishidden(red or shad)
					if(r1.isConditionSubsetOrEquivalent(r2)){
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.REDUNDANT;
						else
							return ConflictType.SHADOWED;
						}
					else if(r2.isConditionSubset(r1)){
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.LESS_but_NOT_CONFLICTING;
						else
							return ConflictType.LESS;
						}
					else{
						if(resolver.isActionEquivalent(r1, r2))
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
						else
							return ConflictType.CONFLICTING;
					}

				}
				if(res == ResolutionComparison.EQUIVALENT){
					if(!resolver.isActionEquivalent(r1, r2))
						return ConflictType.RESOLUTION_ERROR_state_impossible;
					else
						if(r1.isConditionEquivalent(r2))
							return ConflictType.EQUIVALENT;
						else if(r1.isConditionSubset(r2))
							return ConflictType.REDUNDANT;
						else if(r2.isConditionSubset(r1))
							return ConflictType.MAKES_REDUNDANT;
						else
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
				}
				
				if(res == ResolutionComparison.NON_UNIVERSALLY_COMPARABLE)
				{
					System.err.println("This should be implemented for the general instance");
					//throw new Exception();
				}
				
//				if(r1.isConditionEquivalent(r2) && resolver.compare(r1, r2) == ResolutionComparison.EQUIVALENT)
//					return ConflictType.EQUIVALENT;
				
			} catch (NoExternalDataException e) {
				e.printStackTrace();
			} catch (DuplicatedRuleException e) {
				e.printStackTrace();
			} catch (UnmanagedRuleException e) {
				e.printStackTrace();
			}
			
			return ConflictType.CONFLICTING;
	}
	
	/**
	 * Gets the anomalies external.
	 *
	 * @param external the external
	 * @param internalRule the internal rule
	 * @return the anomalies external
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	public ConflictType getAnomaliesExternal(GenericRule external, GenericRule internalRule) throws UnmanagedRuleException{
		
		if(!policy.containsRule(internalRule))
			throw new UnmanagedRuleException();
		
		return private_classify(external, internalRule);	
	}

	/**
	 * Gets the anomalies external.
	 *
	 * @param <S> the generic type
	 * @param externalRule the external rule
	 * @param externalData the external data
	 * @param internalRule the internal rule
	 * @return the anomalies external
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 */
	public <S> ConflictType getAnomaliesExternal(GenericRule externalRule, S externalData, GenericRule internalRule) throws UnmanagedRuleException, IncompatibleExternalDataException, DuplicateExternalDataException{
		
		if(!policy.containsRule(internalRule))
			throw new UnmanagedRuleException();

		if(!(this.resolver instanceof ExternalDataResolutionStrategy)){
			throw new IncompatibleExternalDataException();
		}

		@SuppressWarnings("unchecked")
		ExternalDataResolutionStrategy<GenericRule,S> edstrategy = (ExternalDataResolutionStrategy<GenericRule, S>) 
		this.policy.getResolutionStrategy().cloneResolutionStrategy();
		edstrategy.setExternalData(externalRule, externalData);

		
		return private_classify_external(externalRule, internalRule, edstrategy);	
	}
	
	/**
	 * Gets the all anomalies external.
	 *
	 * @param <S> the generic type
	 * @param externalRule the external rule
	 * @param externalData the external data
	 * @return the all anomalies external
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 */
	public <S> HashMap<GenericRule, ConflictType> getAllAnomaliesExternal(GenericRule externalRule, S externalData) throws IncompatibleExternalDataException, DuplicateExternalDataException{
		
		if(!(this.resolver instanceof ExternalDataResolutionStrategy)){
			throw new IncompatibleExternalDataException();
		}
					
		@SuppressWarnings("unchecked")
		ExternalDataResolutionStrategy<GenericRule,S> edstrategy = (ExternalDataResolutionStrategy<GenericRule, S>) 
									this.policy.getResolutionStrategy().cloneResolutionStrategy();
		edstrategy.setExternalData(externalRule, externalData);
		
		
		HashMap<GenericRule, ConflictType> cth=null;
		try {
			cth = new HashMap<GenericRule, ConflictType>((int)(this.policy.size()/.75));
		} catch (Exception e) {
			e.printStackTrace();
		}
		for(GenericRule internalRule: rules){
			cth.put(internalRule, private_classify_external(externalRule, internalRule, edstrategy));
		}			
	
		return cth;

		
	}
	
	/**
	 * Private_classify_external.
	 *
	 * @param <S> the generic type
	 * @param externalRule the external rule
	 * @param internalRule the internal rule
	 * @param resolver the resolver
	 * @return the conflict type
	 */
	private <S> ConflictType private_classify_external(GenericRule externalRule, GenericRule internalRule, GenericConflictResolutionStrategy resolver){
		if(externalRule.equals(internalRule))
			return ConflictType.IDENTICAL;
		
		if(!externalRule.isIntersecting(internalRule)) 
			return ConflictType.NON_INTERSECTING;
		
		ResolutionComparison res;
			
			try {
				
				res = resolver.compare(externalRule, internalRule);
				
				if(res == ResolutionComparison.UNIVERSALLY_GREATER){ // greater (conf, non conf), hides(makes_red || shadows)
					if(internalRule.isConditionSubsetOrEquivalent(externalRule)){
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.MAKES_REDUNDANT;
						else
							return ConflictType.SHADOWS;
					}
					else if(externalRule.isConditionSubset(internalRule)){
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.GREATER_but_NOT_CONFLICTING;
						else
							return ConflictType.GREATER;
					}
					else{
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
						else
							return ConflictType.CONFLICTING;
					}
				}
				if(res == ResolutionComparison.UNIVERSALLY_LESS){ //less (conf , non conf), ishidden(red or shad)
					if(externalRule.isConditionSubsetOrEquivalent(internalRule)){
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.REDUNDANT;
						else
							return ConflictType.SHADOWED;
						}
					else if(internalRule.isConditionSubset(externalRule)){
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.LESS_but_NOT_CONFLICTING;
						else
							return ConflictType.LESS;
						}
					else{
						if(resolver.isActionEquivalent(externalRule, internalRule))
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
						else
							return ConflictType.CONFLICTING;
					}

				}
				if(res == ResolutionComparison.EQUIVALENT){
					if(!resolver.isActionEquivalent(externalRule, internalRule))
						return ConflictType.RESOLUTION_ERROR_state_impossible;
					else
						if(externalRule.isConditionEquivalent(internalRule))
							return ConflictType.EQUIVALENT;
						else if(externalRule.isConditionSubset(internalRule))
							return ConflictType.REDUNDANT;
						else if(internalRule.isConditionSubset(externalRule))
							return ConflictType.MAKES_REDUNDANT;
						else
							return ConflictType.INTERSECTING_but_NOT_CONFLICTING;
				}
				
				if(res == ResolutionComparison.NON_UNIVERSALLY_COMPARABLE)
				{
					System.err.println("This should be implemented for the general instance");
					//throw new Exception();
				}
				
//				if(r1.isConditionEquivalent(r2) && resolver.compare(r1, r2) == ResolutionComparison.EQUIVALENT)
//					return ConflictType.EQUIVALENT;
				
			} catch (NoExternalDataException e) {
				e.printStackTrace();
			} catch (DuplicatedRuleException e) {
				e.printStackTrace();
			} catch (UnmanagedRuleException e) {
				e.printStackTrace();
			}
			
			return ConflictType.CONFLICTING;

	}

	/**
	 * Gets the all anomalies.
	 *
	 * @param rule the rule
	 * @return the all anomalies
	 */
	public HashMap<GenericRule, ConflictType> getAllAnomalies(GenericRule rule)
	{
		HashMap<GenericRule, ConflictType> cth = new HashMap<GenericRule, ConflictType>();
		for(GenericRule item: rules){
			try {
//				if (!rule.equals(item))
					cth.put(item, getAnomalies(rule, item));
			} catch (UnmanagedRuleException e) {
				e.printStackTrace();
			}			
		}
		return cth;
	}

	/**
	 * Gets the all anomalies external.
	 *
	 * @param rule the rule
	 * @return the all anomalies external
	 */
	public HashMap<GenericRule,ConflictType> getAllAnomaliesExternal(GenericRule rule)
	{
		HashMap<GenericRule, ConflictType> cth=null;
		try {
			cth = new HashMap<GenericRule, ConflictType>((int)(this.policy.size()/.75));
			
			for(GenericRule item: rules){
				cth.put(item, getAnomaliesExternal(rule, item));
			}
		} catch (UnmanagedRuleException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}			
	
		return cth;
	}

}
