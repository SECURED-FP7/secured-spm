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

import dk.brics.automaton.Automaton;
import dk.brics.automaton.BasicOperations;
import dk.brics.automaton.OtherOperations;
import dk.brics.automaton.RegExp;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class StandardRegExpSelector.
 */
public class StandardRegExpSelector implements RegExpSelector, Cloneable {

	/**
	 * The Enum RegexState.
	 */
	private enum RegexState {
		
		/** The value. */
		VALUE, 
 /** The full. */
 FULL, 
 /** The empty. */
 EMPTY;
	}

	/** The state. */
	RegexState state;
	
	/** The automata. */
	Automaton automata;
	
	/** The regex. */
	RegExp regex;

	/**
	 * Instantiates a new standard reg exp selector.
	 */
	public StandardRegExpSelector() {
		state = RegexState.FULL;
	}

	/**
	 * Instantiates a new standard reg exp selector.
	 *
	 * @param s the s
	 */
	public StandardRegExpSelector(String s) {
		this.regex = new RegExp(s);
		this.automata = this.regex.toAutomaton();
		state = RegexState.VALUE;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	public boolean isPoint() {
		if (automata != null)
			return automata.isSingleton();

		return false;
	}

	/**
	 * Adds the range.
	 *
	 * @param regexp the regexp
	 */
	public void addRange(String regexp) {

		// if(regexp.equals(".*")){
		// automata = null;
		// regex = null;
		// state = RegexState.FULL;
		// return;
		// }
		//
		// if (regexp.startsWith("^"))
		// regexp = regexp.substring(1);
		// else if(!regexp.startsWith(".*")){
		// regexp = ".*" + regexp;
		// }
		//
		// if (regexp.endsWith("$"))
		// regexp = regexp.substring(0, regexp.length()-1);
		// else if(! regexp.endsWith(".*"))
		// regexp = regexp.concat(".*");

		// this.regex = ;

		RegExp r = new RegExp(regexp);
		if (automata == null)
			automata = r.toAutomaton();
		else
			automata = automata.union(r.toAutomaton());

		state = RegexState.VALUE;
		// TODO: aggiornare regex con automaton->regex

	}

	/**
	 * Gets the automaton.
	 *
	 * @return the automaton
	 */
	public Automaton getAutomaton() {
		return automata.clone();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		automata = null;
		regex = null;
		state = RegexState.EMPTY;

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public Selector selectorClone() {
		return clone();

	}

	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	public StandardRegExpSelector clone() {
		StandardRegExpSelector clone = new StandardRegExpSelector();
		if (automata != null)
			clone.automata = automata.clone();
		if (regex != null)
			clone.regex = new RegExp(regex.toString());
		clone.state = state;

		return clone;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		if (state == RegexState.EMPTY)
			return true;

		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		if (state == RegexState.FULL)
			return true;

		return false;
	}

	/**
	 * Copy selector.
	 *
	 * @param s the s
	 */
	private void copySelector(StandardRegExpSelector s) {

		if (s.automata != null)
			automata = s.automata.clone();
		else
			automata = null;
		if (s.regex != null)
			regex = new RegExp(s.regex.toString());
		else
			regex = null;

		state = s.state;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isFull())
			return;

		if (this.isFull() || s.isEmpty()) {
			copySelector((StandardRegExpSelector) s);
			return;
		}

		automata = BasicOperations.intersection(automata,
				((StandardRegExpSelector) s).automata);

		if (automata.isEmpty()) {
			automata = null;
			regex = null;
			state = RegexState.EMPTY;
		}

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (isEmpty() || s.isFull()) {
			copySelector((StandardRegExpSelector) s);
			return;
		}

		if (isFull() || s.isEmpty())
			return;

		automata = BasicOperations.union(automata,
				((StandardRegExpSelector) s).automata);

		// Potrebbe diventare pieno ma sembra impossibile.....
	}

	// @Override
	// public void setMinus(Selector s) throws IllegalArgumentException {
	// if (isEmpty() || s.isEmpty()) {
	// return;
	// }
	//
	// if (s.isFull()){
	// automata = null;
	// regex = null;
	// state = RegexState.EMPTY;
	// return;
	// }
	//
	// if (isFull()){
	// automata =
	// BasicOperations.complement(((StandardRegExpSelector)s).automata);
	// regex=null;
	// state = RegexState.VALUE;
	// return;
	// }
	//
	// automata = BasicOperations.minus(automata, ((StandardRegExpSelector)
	// s).automata);
	//
	// }

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	@Override
	public void complement() {
		if (isEmpty()) {
			state = RegexState.FULL;
			automata = null;
			regex = null;
			return;
		}

		if (isFull()) {
			state = RegexState.EMPTY;
			automata = null;
			regex = null;
			return;
		}

		automata = automata.complement();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull() || s.isFull())
			return true;

		return OtherOperations.intersecting(automata,
				((StandardRegExpSelector) s).automata);

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;

		if (s.isEmpty())
			return false;
		else if (this.isFull() && s.isFull())
			return true;

		return OtherOperations.equivalent(automata,
				((StandardRegExpSelector) s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		// TODO: Vedere con aldo questa parte teorica. L'insieme vuoto subset di
		// ogni set,
		// una regola con un campo vuoto ha senso? nn matcha mai quindi a che
		// serve?
		// come si relaziona con le altre?
		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull())
			return false;

		if (s.isFull())
			return true;

		return OtherOperations.subsetNotEquivalent(automata,
				((StandardRegExpSelector) s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s)
			throws IllegalArgumentException {
		// Come sopra per is empty
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;

		if (s.isFull())
			return true;

		return BasicOperations.subsetOf(automata,
				((StandardRegExpSelector) s).automata);

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		return toString();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.RegExpSelector#setRegExp(java.lang.String)
	 */
	@Override
	public void setRegExp(String regexp) {

	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (isFull())
			return "*";
		if (isEmpty())
			return "empty";

		if (regex == null){
			if (automata != null) {
				regex = new RegExp(OtherOperations.toRegExp(automata));
				return regex.toString().replace("\"", "").replace("(\\/)", "/");
			}
		}else{
			return regex.toString().replace("\"", "");
		}

		return "";
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	@Override
	public int getFirstAssignedValue() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		automata = null;
		regex = null;
		state = RegexState.FULL;
	}

}
