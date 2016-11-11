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
package eu.fp7.secured.rule.impl;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.selector.Selector;


/**
 * The Class NATRule.
 */
public class NATRule extends GenericRule{

	/** The rules. */
	private HashSet<GenericRule> rules;
	
	/** The nat condition. */
	private ConditionClause natCondition;
	
	/**
	 * Instantiates a new NAT rule.
	 *
	 * @param action the action
	 * @param conditionClause the condition clause
	 * @param name the name
	 * @param MSPL the mspl
	 * @param HSPL the hspl
	 */
	public NATRule(Action action, ConditionClause conditionClause, String name, HashSet<String> MSPL, List<HSPL> HSPL){
		super(action, conditionClause, name, MSPL, HSPL);
		rules = new HashSet<GenericRule>();
	}
	
	/**
	 * Sets the NAT rule.
	 *
	 * @param natCondition the new NAT rule
	 */
	public void setNATRule(ConditionClause natCondition){
		this.natCondition = natCondition;
	}
	
	/**
	 * Gets the NAT rule.
	 *
	 * @return the NAT rule
	 */
	public ConditionClause getNATRule() {
		return natCondition;
	}

	/**
	 * Gets the original rules.
	 *
	 * @return the original rules
	 */
	public HashSet<GenericRule> getOriginalRules(){
		return rules;
	}
	
	/**
	 * Adds the original rule.
	 *
	 * @param rule the rule
	 */
	public void addOriginalRule(GenericRule rule){
		if(rule instanceof NATRule)
			addAllOriginalRules(((NATRule) rule).getOriginalRules());
		else
			rules.add(rule);
	}
	
	/**
	 * Delet original rule.
	 *
	 * @param rule the rule
	 */
	public void deletOriginalRule(GenericRule rule){
		rules.remove(rule);
	}
	
	/**
	 * Adds the all original rules.
	 *
	 * @param rules the rules
	 */
	public void addAllOriginalRules(LinkedList<GenericRule> rules){
		for(GenericRule rule:rules){
			if(rule instanceof NATRule){
				NATRule nr=(NATRule)rule;
				addAllOriginalRules(nr.getOriginalRules());
			} else
				addOriginalRule(rule);
		}
		
		
	}
	
	/**
	 * Adds the all original rules.
	 *
	 * @param rules the rules
	 */
	private void addAllOriginalRules(HashSet<GenericRule> rules){
		this.rules.addAll(rules);
	}
	
}
