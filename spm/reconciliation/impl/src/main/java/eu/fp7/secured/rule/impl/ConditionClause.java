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
import java.util.LinkedHashSet;
import java.util.Set;

import dk.brics.automaton.Automaton;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;

/**
 * The Class ConditionClause.
 */
public class ConditionClause {

	/** The selectors. */
	private LinkedHashMap<String, Selector> selectors;

	/**
	 * Instantiates a new condition clause.
	 *
	 * @param selectors the selectors
	 */
	public ConditionClause(LinkedHashMap<String, Selector> selectors) {
		this.selectors = selectors;
	}

	/**
	 * Gets the selectors.
	 *
	 * @return the selectors
	 */
	private LinkedHashMap<String, Selector> getSelectors() {
		return selectors;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		for (String s : selectors.keySet()) {
			sb.append(s);
			sb.append(':');
			sb.append(selectors.get(s));
			sb.append('\n');
		}
		return sb.toString();
	}
	
	/**
	 * Gets the.
	 *
	 * @param name the name
	 * @return the selector
	 */
	public Selector get(String name){
		return selectors.get(name);
	}
	
	/**
	 * Gets the selectors names.
	 *
	 * @return the selectors names
	 */
	public Set<String> getSelectorsNames(){
		if(selectors==null)
			return new HashSet<String>();
		return selectors.keySet();
	}
	
	/**
	 * Condition clause clone.
	 *
	 * @return the condition clause
	 */
	public ConditionClause conditionClauseClone(){
		LinkedHashMap<String, Selector> selectorsClone = new LinkedHashMap<String, Selector>();
		
		for(String name:selectors.keySet()){
			selectorsClone.put(name, selectors.get(name).selectorClone());
		}
		
		return new ConditionClause(selectorsClone);
	}

	/**
	 * Intersection.
	 *
	 * @param c the c
	 */
	public void intersection(ConditionClause c) {

		HashMap<String, Selector> ext = c.getSelectors();

		if (ext == null)
			this.selectors = null;
		
		if (this.selectors == null)
			return;
		


		for (String lab : this.selectors.keySet()) {
			Selector sint = this.selectors.get(lab);
			Selector sext = ext.get(lab);

			if (sext != null) {
				sint.intersection(sext);
				if (sint.isEmpty()) {
					this.selectors = null;
					return;
				}
			} else {
				selectors.put(lab, sint.selectorClone());
			}
		}

		for (String lab : ext.keySet()) {
			Selector sint = this.selectors.get(lab);
			if (sint == null) {
				selectors.put(lab, ext.get(lab).selectorClone());
			}
		}

	}

	/**
	 * Checks if is condition equivalent.
	 *
	 * @param c the c
	 * @return true, if is condition equivalent
	 */
	public boolean isConditionEquivalent(ConditionClause c) {
		LinkedHashMap<String, Selector> ext = c.getSelectors();

		if (this.selectors == null && ext == null)
			return true;

		if (this.selectors == null || ext == null)
			return false;

		LinkedHashSet<String> selectorNames = new LinkedHashSet<String>();

		selectorNames.addAll(ext.keySet());
		selectorNames.addAll(selectors.keySet());

		for (String lab : selectorNames) {
			Selector sint = selectors.get(lab);
			Selector sext = ext.get(lab);

			if (sint == null) {
				if (sext != null)
					if (!sext.isFull())
						return false;
					else
						ext.remove(lab);
			} else {
				if (sext == null) {
					if (!sint.isFull())
						return false;
					else
						selectors.remove(lab);
				} else if (!sint.isEquivalent(sext))
					return false;
			}

		}
		return true;
	}

	/**
	 * Checks if is condition subset.
	 *
	 * @param c the c
	 * @return true, if is condition subset
	 */
	public boolean isConditionSubset(ConditionClause c) {
		HashMap<String, Selector> ext = c.getSelectors();

		if (this.selectors == null || ext == null)
			return false;

		// ext = rext.getHashapSelector();
		boolean atLeastOne = false;

		for (String s : ext.keySet()) {
			Selector s1 = selectors.get(s);
			Selector s2 = ext.get(s);
			if (s1 != null) {
				if (s1.isSubset(s2))
					atLeastOne = true;
				else if (!s1.isEquivalent(s2))
					return false;
			} else if (!s2.isFull())
				return false;

		}

		return atLeastOne;
	}

	/**
	 * Checks if is condition subset or equivalent.
	 *
	 * @param c the c
	 * @return true, if is condition subset or equivalent
	 */
	public boolean isConditionSubsetOrEquivalent(ConditionClause c) {
		HashMap<String, Selector> ext = c.getSelectors();

		if (this.selectors == null || ext == null)
			return false;

		for (String s : ext.keySet()) {
			Selector s1 = selectors.get(s);
			Selector s2 = ext.get(s);
			if (s1 != null) {
				if (!s1.isSubsetOrEquivalent(s2))
					return false;
			} else if (!s2.isFull())
				return false;
		}
		return true;
	}

	/**
	 * Checks if is correlated.
	 *
	 * @param c the c
	 * @return true, if is correlated
	 */
	public boolean isCorrelated(ConditionClause c) {
		HashMap<String, Selector> ext = c.getSelectors();

		if (this.selectors == null || ext == null)
			return false;

		for (String s : ext.keySet()) {
			Selector s1 = selectors.get(s);
			Selector s2 = ext.get(s);
			if (s1 != null) {
				if (!s1.isSubsetOrEquivalent(s2) || !s2.isSubset(s1))
					return false;
			} else if (!s2.isFull())
				return false;
		}
		return true;
	}

	/**
	 * Checks if is empty.
	 *
	 * @return true, if is empty
	 */
	public boolean isEmpty() {

		if (selectors == null)
			return true;
		
		for(String s:selectors.keySet()){
			if(selectors.get(s).isEmpty())
				return true;
		}

		return false;
	}

	/**
	 * Checks if is intersecting.
	 *
	 * @param c the c
	 * @return true, if is intersecting
	 */
	public boolean isIntersecting(ConditionClause c) {
		HashMap<String, Selector> ext = c.getSelectors();

		if (this.selectors == null || ext == null)
			return false;

		for (String label : selectors.keySet()) {
			Selector sInt = selectors.get(label);
			Selector sExt = ext.get(label);

			if (sExt != null)
				if (!sInt.isIntersecting(sExt))
					return false;
		}
		return true;
	}

	/**
	 * Gets the equivalence class.
	 *
	 * @param selectorNames the selector names
	 * @return the equivalence class
	 */
	public long getEquivalenceClass(HashSet<String> selectorNames) {
		
		String[] orderedLabels = selectorNames.toArray(new String[selectorNames.size()]);

		long eqClass = 0;
		int countNF = 0;
		int posFirstRegex = -1;
		int posFirstNF = -1;

		for (int i = 0; i < orderedLabels.length; i++)
			if (selectors.get(orderedLabels[i]) != null) {
				if (countNF == 0) {
					eqClass += i;
					eqClass <<= 24;
					countNF++;
					posFirstNF = i;
				} else {
					countNF++;
				}

				if (posFirstRegex == -1) {
					if (selectors.get(orderedLabels[i]) instanceof RegExpSelector)
						posFirstRegex = i;
					// countNF++;
				}

			}

		if (posFirstNF >= 0)
			eqClass += selectors.get(orderedLabels[posFirstNF])
					.getFirstAssignedValue();
		eqClass <<= 14;

		eqClass += countNF;
		eqClass <<= 6;

		if (posFirstRegex == -1)
			eqClass <<= 14;
		else {
			Automaton a = ((StandardRegExpSelector) selectors
					.get(orderedLabels[posFirstRegex])).getAutomaton();
			eqClass += (a.getNumberOfStates() % 64);
			eqClass <<= 6;
			eqClass += (a.getNumberOfTransitions() % 64);
			eqClass <<= 8;
			eqClass += (((int) a.getInitialState().getSortedTransitions(true)
					.get(0).getMax()) % 256);
		}

		return eqClass;
	}

	
	/**
	 * Sets the selector.
	 *
	 * @param selctorName the selctor name
	 * @param selector the selector
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 */
	public void setSelector(String selctorName, Selector selector) throws IncompatibleSelectorException{
		if(selectors.containsKey(selctorName))
			if(selectors.get(selctorName).getClass() != selector.getClass())
				throw new IncompatibleSelectorException();
		selectors.put(selctorName, selector);
	}
	
	/**
	 * Checks if is point.
	 *
	 * @param selctorsName the selctors name
	 * @return true, if is point
	 */
	public boolean isPoint(Set<String> selctorsName){
		if(selectors==null)
			return false;
		
		for(String s:selctorsName){
			if(selectors.get(s)==null)
				return false;
			
			if(!selectors.get(s).isPoint())
				return false;
		}
		
		return true;
	}
}
