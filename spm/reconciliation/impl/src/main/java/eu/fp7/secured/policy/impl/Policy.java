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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.OperationNotPermittedException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Interface Policy.
 */
public interface Policy extends Cloneable{
	
	/**
	 * Gets the name.
	 *
	 * @return the name
	 */
	public String getName();
	
	/**
	 * Gets the creator.
	 *
	 * @return the creator
	 */
	public String getCreator();

	/**
	 * Gets the capability.
	 *
	 * @return the capability
	 */
	public List<Capability> getCapability();
	
	/**
	 * Insert rule.
	 *
	 * @param rule the rule
	 * @throws NoExternalDataException the no external data exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	public void insertRule(GenericRule rule) throws NoExternalDataException, OperationNotPermittedException, UnsupportedSelectorException;
	
	/**
	 * Insert rule.
	 *
	 * @param <S> the generic type
	 * @param rule the rule
	 * @param externalData the external data
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	public <S> void insertRule(GenericRule rule, S externalData) throws IncompatibleExternalDataException, DuplicateExternalDataException, OperationNotPermittedException, UnsupportedSelectorException;
	
	/**
	 * Insert all.
	 *
	 * @param rules the rules
	 * @throws NoExternalDataException the no external data exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 */
	public void insertAll(Collection<GenericRule> rules) throws NoExternalDataException, OperationNotPermittedException;
	
	/**
	 * Insert all.
	 *
	 * @param <S> the generic type
	 * @param rules the rules
	 * @throws NoExternalDataException the no external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 */
	public <S> void insertAll(HashMap<GenericRule,S> rules) throws NoExternalDataException, IncompatibleExternalDataException, DuplicateExternalDataException, OperationNotPermittedException;
	
	/**
	 * Removes the rule.
	 *
	 * @param rule the rule
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 */
	public void removeRule(GenericRule rule) throws UnmanagedRuleException, OperationNotPermittedException;
	
	/**
	 * Removes the all.
	 *
	 * @param rules the rules
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws OperationNotPermittedException the operation not permitted exception
	 */
	public void removeAll(Collection<GenericRule> rules) throws UnmanagedRuleException, OperationNotPermittedException;
	
	/**
	 * Contains rule.
	 *
	 * @param rule the rule
	 * @return true, if successful
	 */
	public boolean containsRule(GenericRule rule);
	
	/**
	 * Clear rules.
	 *
	 * @throws OperationNotPermittedException the operation not permitted exception
	 */
	public void clearRules() throws OperationNotPermittedException;

	/**
	 * Gets the default action.
	 *
	 * @return the default action
	 */
	public Action getDefaultAction();

	/**
	 * Gets the resolution strategy.
	 *
	 * @return the resolution strategy
	 */
	public GenericConflictResolutionStrategy getResolutionStrategy() ;

	/**
	 * Gets the rule set.
	 *
	 * @return the rule set
	 */
	public Set<GenericRule> getRuleSet();

	/**
	 * Size.
	 *
	 * @return the int
	 */
	public int size();
	
	/**
	 * Gets the selector names.
	 *
	 * @return the selector names
	 */
	public HashSet<String>  getSelectorNames();
	
	/**
	 * To string.
	 *
	 * @return the string
	 */
	@Override
	public String toString();

	/**
	 * Eval action.
	 *
	 * @param punto the punto
	 * @return the action
	 * @throws Exception the exception
	 */
	public Action evalAction(ConditionClause punto) throws Exception; 

	/**
	 * Match.
	 *
	 * @param point the point
	 * @return the hash set
	 * @throws Exception the exception
	 */
	public HashSet<GenericRule> match(ConditionClause point) throws Exception;
	
	/**
	 * Policy clone.
	 *
	 * @return the policy
	 */
	public Policy policyClone();
	
	/**
	 * Gets the rule classifier.
	 *
	 * @return the rule classifier
	 */
	public RuleClassifier getRuleClassifier();
	
}