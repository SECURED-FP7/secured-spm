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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.rule.action.Action;

/**
 * The Class GenericRule.
 */
public class GenericRule {

	/** The condition clause. */
	private ConditionClause conditionClause;
	
	/** The action. */
	private Action action;
	
	/** The name. */
	private String name = "";
	
	/** The MSP l_id. */
	private HashSet<String> MSPL_id;
	
	/** The HSP ls. */
	private List<HSPL> HSPLs;
	
	
	/**
	 * Gets the MSP l_id.
	 *
	 * @return the MSP l_id
	 */
	public HashSet<String> getMSPL_id() {
		return this.MSPL_id;
	}
	
	/**
	 * Gets the HSP ls.
	 *
	 * @return the HSP ls
	 */
	public List<HSPL> getHSPLs() {
		return this.HSPLs;
	}

	/**
	 * Instantiates a new generic rule.
	 *
	 * @param action the action
	 * @param conditionClause the condition clause
	 * @param name the name
	 * @param MSPL_id the MSP l_id
	 * @param HSPLs the HSP ls
	 */
	public GenericRule(Action action, ConditionClause conditionClause, String name, HashSet<String> MSPL_id, List<HSPL> HSPLs) {
		this.conditionClause = conditionClause;
		this.action = action;
		this.name = name;
		this.HSPLs = HSPLs;
		this.MSPL_id = MSPL_id;
	}

	/**
	 * Gets the name.
	 *
	 * @return the name
	 */
	public String getName() {
		if (name == null)
			return "";
		return name;
	}

	// public void setName(String label) {
	// this.name = label;
	// }

	/**
	 * Gets the action.
	 *
	 * @return the action
	 */
	public Action getAction() {
		return action;
	}

	// public void setAction(Action a) {
	// this.action = a;
	// }

//	public void setConditionClause(ConditionClause conditionClause) {
//		this.conditionClause = conditionClause;
//	}

	/**
	 * Gets the condition clause.
	 *
	 * @return the condition clause
	 */
	public ConditionClause getConditionClause() {
		return conditionClause;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		String str = "";

		if (name != null)
			if (!name.equalsIgnoreCase(""))
				str = name + "\n";

		str += conditionClause.toString();

		str += ("Action: " + action);
		return str;
	}

	/**
	 * Checks if is empty.
	 *
	 * @return true, if is empty
	 */
	public boolean isEmpty() {
		return conditionClause.isEmpty();
	}

	/**
	 * Checks if is condition equivalent.
	 *
	 * @param c the c
	 * @return true, if is condition equivalent
	 */
	public boolean isConditionEquivalent(ConditionClause c) {
		return conditionClause.isConditionEquivalent(c);
	}

	/**
	 * Checks if is condition subset.
	 *
	 * @param c the c
	 * @return true, if is condition subset
	 */
	public boolean isConditionSubset(ConditionClause c) {
		return conditionClause.isConditionSubset(c);
	}

	/**
	 * Checks if is condition subset or equivalent.
	 *
	 * @param c the c
	 * @return true, if is condition subset or equivalent
	 */
	public boolean isConditionSubsetOrEquivalent(ConditionClause c) {
		return conditionClause.isConditionSubsetOrEquivalent(c);
	}

	/**
	 * Checks if is correlated.
	 *
	 * @param c the c
	 * @return true, if is correlated
	 */
	public boolean isCorrelated(ConditionClause c) {
		return conditionClause.isCorrelated(c);
	}

	/**
	 * Checks if is intersecting.
	 *
	 * @param r the r
	 * @return true, if is intersecting
	 */
	public boolean isIntersecting(GenericRule r) {
		return conditionClause.isIntersecting(r.getConditionClause());
	}

	/**
	 * Checks if is condition equivalent.
	 *
	 * @param r the r
	 * @return true, if is condition equivalent
	 */
	public boolean isConditionEquivalent(GenericRule r) {
		return conditionClause.isConditionEquivalent(r.getConditionClause());
	}

	/**
	 * Checks if is condition subset.
	 *
	 * @param r the r
	 * @return true, if is condition subset
	 */
	public boolean isConditionSubset(GenericRule r) {
		return conditionClause.isConditionSubset(r.getConditionClause());
	}

	/**
	 * Checks if is condition subset or equivalent.
	 *
	 * @param r the r
	 * @return true, if is condition subset or equivalent
	 */
	public boolean isConditionSubsetOrEquivalent(GenericRule r) {
		return conditionClause.isConditionSubsetOrEquivalent(r.getConditionClause());
	}

	/**
	 * Checks if is correlated.
	 *
	 * @param r the r
	 * @return true, if is correlated
	 */
	public boolean isCorrelated(GenericRule r) {
		return conditionClause.isCorrelated(r.getConditionClause());
	}

	/**
	 * Checks if is intersecting.
	 *
	 * @param c the c
	 * @return true, if is intersecting
	 */
	public boolean isIntersecting(ConditionClause c) {
		return conditionClause.isIntersecting(c);
	}

	/**
	 * Gets the equivalence class.
	 *
	 * @param selectorNames the selector names
	 * @return the equivalence class
	 */
	public long getEquivalenceClass(HashSet<String> selectorNames) {
		return conditionClause.getEquivalenceClass(selectorNames);
	}

	/**
	 * Rule clone.
	 *
	 * @return the generic rule
	 */
	public GenericRule ruleClone(){
		List<HSPL> Hs = new LinkedList<>();
		for (HSPL hspl:this.HSPLs){
			HSPL h = new HSPL();
			h.setHSPLId(hspl.getHSPLId());
			h.setHSPLText(hspl.getHSPLText());
			Hs.add(h);
		}
		
		HashSet<String> mid = new HashSet<>();
		for(String mspl:MSPL_id){
			mid.add(mspl);
		}
		
		return new GenericRule(action.actionClone(), conditionClause.conditionClauseClone(), name, mid, Hs);
	}
}