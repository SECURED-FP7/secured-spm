package eu.fp7.secured.rule.impl;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;

import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.selector.Selector;


public class NATRule extends GenericRule{

	private HashSet<GenericRule> rules;
	private ConditionClause natCondition;
	
	public NATRule(Action action, ConditionClause conditionClause, String name){
		super(action, conditionClause, name);
		rules = new HashSet<GenericRule>();
	}
	
	public void setNATRule(ConditionClause natCondition){
		this.natCondition = natCondition;
	}
	
	public ConditionClause getNATRule() {
		return natCondition;
	}

	public HashSet<GenericRule> getOriginalRules(){
		return rules;
	}
	
	public void addOriginalRule(GenericRule rule){
		if(rule instanceof NATRule)
			addAllOriginalRules(((NATRule) rule).getOriginalRules());
		else
			rules.add(rule);
	}
	
	public void deletOriginalRule(GenericRule rule){
		rules.remove(rule);
	}
	
	public void addAllOriginalRules(LinkedList<GenericRule> rules){
		for(GenericRule rule:rules){
			if(rule instanceof NATRule){
				NATRule nr=(NATRule)rule;
				addAllOriginalRules(nr.getOriginalRules());
			} else
				addOriginalRule(rule);
		}
		
		
	}
	
	private void addAllOriginalRules(HashSet<GenericRule> rules){
		this.rules.addAll(rules);
	}
	
}
