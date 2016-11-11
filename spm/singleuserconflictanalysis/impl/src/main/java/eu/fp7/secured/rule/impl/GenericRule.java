package eu.fp7.secured.rule.impl;

import java.util.HashSet;

import eu.fp7.secured.rule.action.Action;

public class GenericRule {

	private ConditionClause conditionClause;
	private Action action;
	private String name = "";

	public GenericRule(Action action, ConditionClause conditionClause, String name) {
		this.conditionClause = conditionClause;
		this.action = action;
		this.name = name;
	}

	public String getName() {
		if (name == null)
			return "";
		return name;
	}

	// public void setName(String label) {
	// this.name = label;
	// }

	public Action getAction() {
		return action;
	}

	// public void setAction(Action a) {
	// this.action = a;
	// }

//	public void setConditionClause(ConditionClause conditionClause) {
//		this.conditionClause = conditionClause;
//	}

	public ConditionClause getConditionClause() {
		return conditionClause;
	}

	public String toString() {
		String str = "";

		if (name != null)
			if (!name.equalsIgnoreCase(""))
				str = name + "\n";

		str += conditionClause.toString();

		str += ("Action: " + action);
		return str;
	}

	public boolean isEmpty() {
		return conditionClause.isEmpty();
	}

	public boolean isConditionEquivalent(ConditionClause c) {
		return conditionClause.isConditionEquivalent(c);
	}

	public boolean isConditionSubset(ConditionClause c) {
		return conditionClause.isConditionSubset(c);
	}

	public boolean isConditionSubsetOrEquivalent(ConditionClause c) {
		return conditionClause.isConditionSubsetOrEquivalent(c);
	}

	public boolean isCorrelated(ConditionClause c) {
		return conditionClause.isCorrelated(c);
	}

	public boolean isIntersecting(GenericRule r) {
		return conditionClause.isIntersecting(r.getConditionClause());
	}

	public boolean isConditionEquivalent(GenericRule r) {
		return conditionClause.isConditionEquivalent(r.getConditionClause());
	}

	public boolean isConditionSubset(GenericRule r) {
		return conditionClause.isConditionSubset(r.getConditionClause());
	}

	public boolean isConditionSubsetOrEquivalent(GenericRule r) {
		return conditionClause.isConditionSubsetOrEquivalent(r.getConditionClause());
	}

	public boolean isCorrelated(GenericRule r) {
		return conditionClause.isCorrelated(r.getConditionClause());
	}

	public boolean isIntersecting(ConditionClause c) {
		return conditionClause.isIntersecting(c);
	}

	public long getEquivalenceClass(HashSet<String> selectorNames) {
		return conditionClause.getEquivalenceClass(selectorNames);
	}

	public GenericRule ruleClone(){
		return new GenericRule(action.actionClone(), conditionClause.conditionClauseClone(), name);
	}
}