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
package eu.fp7.secured.selector.impl;

import java.util.BitSet;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.BasicOperations;
import dk.brics.automaton.OtherOperations;
import dk.brics.automaton.RegExp;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;



/**
 * The Class DomainSelector.
 */
public class DomainSelector implements ExactMatchSelector {
	
	/** The automata. */
	protected Automaton automata;
	
	/**
	 * Gets the automaton.
	 *
	 * @return the automaton
	 */
	public Automaton getAutomaton(){
		if (automata!=null)
			return automata.clone();
		return new Automaton();
	}
	
	/**
	 * Instantiates a new domain selector.
	 */
	public DomainSelector(){
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	public void addRange(Object regexp) throws InvalidRangeException {
		try {
			String s = (String) regexp;
			addRange(s);
		} catch (ClassCastException e){
			throw new InvalidRangeException("Not a String");
		}	
	}
	
	/**
	 * Adds the range.
	 *
	 * @param regexp the regexp
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String regexp) throws InvalidRangeException {
		
		char [] str = regexp.toCharArray();
		
		StringBuffer sb = new StringBuffer();
		sb.append(str[0]);
		
		for (int i=1;i<str.length;i++){
			if (str[i]=='.')
				sb.append("\\");
			sb.append(str[i]);
		}
		regexp = sb.toString();
		
		if (automata == null)
			automata = (new RegExp(regexp)).toAutomaton();
		else automata = BasicOperations.union(automata,(new RegExp(regexp)).toAutomaton());
		automata.determinize();
		
	}

	//@Override
	//TODO
/*	public BitSet getPointSet() {
		return null;
	}*/

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	@Override
	public void complement() {
		automata = BasicOperations.complement(automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		automata = (new RegExp("")).toAutomaton();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		automata = BasicOperations.intersection(automata, ((DomainSelector)s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return automata.isEmpty();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		return OtherOperations.equivalent(automata, ((DomainSelector)s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		//TODO
		System.err.println("Not yet implemented");
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		return OtherOperations.intersecting(automata, ((DomainSelector)s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		return OtherOperations.subsetNotEquivalent(automata, ((DomainSelector)s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		return BasicOperations.subsetOf(automata, ((DomainSelector)s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public DomainSelector selectorClone() {
		DomainSelector r = new DomainSelector();
		r.automata = automata.clone();
		return r;
	}

//	@Override
//	public void setMinus(Selector s) throws IllegalArgumentException {
//		automata = BasicOperations.minus(automata, ((DomainSelector)s).automata);
//		if (!this.label.equalsIgnoreCase(s.getLabel()))
//			if(!s.getLabel().equals(""))
//				label = label + " && !"+s.getLabel();
//	}

	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
 */
@Override
	public String toSimpleString() {
		return "to implement";
	}
	

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		if (automata!= null)
			return automata.toString();
		return "Empty";
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		automata = BasicOperations.union(automata, ((DomainSelector)s).automata);
		automata.determinize();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getPointSet()
	 */
	@Override
	public BitSet getPointSet() {
		return null;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getElementsNumber()
	 */
	@Override
	public int getElementsNumber() {
		return -1;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	@Override
	public int getFirstAssignedValue() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	@Override
	public boolean isPoint() {
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		
	}

}
