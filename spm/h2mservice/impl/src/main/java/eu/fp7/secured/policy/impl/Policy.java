package eu.fp7.secured.policy.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.OperationNotPermittedException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.utils.PolicyType;
import eu.fp7.secured.policy.utils.RuleClassifier;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;


public interface Policy extends Cloneable{
	
	public String getName();
	
	public PolicyType getPolicyType();
	
	public void insertRule(GenericRule rule) throws NoExternalDataException, OperationNotPermittedException, UnsupportedSelectorException;
	
	public <S> void insertRule(GenericRule rule, S externalData) throws IncompatibleExternalDataException, DuplicateExternalDataException, OperationNotPermittedException, UnsupportedSelectorException;
	
	public void insertAll(Collection<GenericRule> rules) throws NoExternalDataException, OperationNotPermittedException;
	
	public <S> void insertAll(HashMap<GenericRule,S> rules) throws NoExternalDataException, IncompatibleExternalDataException, DuplicateExternalDataException, OperationNotPermittedException;
	
	public void removeRule(GenericRule rule) throws UnmanagedRuleException, OperationNotPermittedException;
	
	public void removeAll(Collection<GenericRule> rules) throws UnmanagedRuleException, OperationNotPermittedException;
	
	public boolean containsRule(GenericRule rule);
	
	public void clearRules() throws OperationNotPermittedException;

	public Action getDefaultAction();

	public GenericConflictResolutionStrategy getResolutionStrategy() ;

	public Set<GenericRule> getRuleSet();

	public int size();
	
	public HashSet<String>  getSelectorNames();
	
	@Override
	public String toString();

	public Action evalAction(ConditionClause punto) throws Exception; 

	public HashSet<GenericRule> match(ConditionClause point) throws Exception;
	
	public Policy policyClone();
	
	public RuleClassifier getRuleClassifier();
	
}