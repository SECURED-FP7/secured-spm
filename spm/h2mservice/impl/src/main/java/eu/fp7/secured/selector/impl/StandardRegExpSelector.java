package eu.fp7.secured.selector.impl;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.BasicOperations;
import dk.brics.automaton.OtherOperations;
import dk.brics.automaton.RegExp;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;

public class StandardRegExpSelector implements RegExpSelector, Cloneable {

	private enum RegexState {
		VALUE, FULL, EMPTY;
	}

	RegexState state;
	Automaton automata;
	RegExp regex;

	public StandardRegExpSelector() {
		state = RegexState.FULL;
	}

	public StandardRegExpSelector(String s) {
		this.regex = new RegExp(s);
		this.automata = this.regex.toAutomaton();
		state = RegexState.VALUE;
	}

	public boolean isPoint() {
		if (automata != null)
			return automata.isSingleton();

		return false;
	}

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

	public Automaton getAutomaton() {
		return automata.clone();
	}

	@Override
	public void empty() {
		automata = null;
		regex = null;
		state = RegexState.EMPTY;

	}

	@Override
	public Selector selectorClone() {
		return clone();

	}

	public StandardRegExpSelector clone() {
		StandardRegExpSelector clone = new StandardRegExpSelector();
		if (automata != null)
			clone.automata = automata.clone();
		if (regex != null)
			clone.regex = new RegExp(regex.toString());
		clone.state = state;

		return clone;
	}

	@Override
	public boolean isEmpty() {
		if (state == RegexState.EMPTY)
			return true;

		return false;
	}

	@Override
	public boolean isFull() {
		if (state == RegexState.FULL)
			return true;

		return false;
	}

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

	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull() || s.isFull())
			return true;

		return OtherOperations.intersecting(automata,
				((StandardRegExpSelector) s).automata);

	}

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

	@Override
	public String toSimpleString() {
		return toString();
	}

	@Override
	public long length() {
		return 0;
	}

	@Override
	public void setRegExp(String regexp) {

	}

	@Override
	public String toString() {
		if (isFull())
			return "*";
		if (isEmpty())
			return "empty";

		if (regex == null){
			if (automata != null) {
				regex = new RegExp(OtherOperations.toRegExp(automata));
				return regex.toString().replace("\"", "");
			}
		}else{
			return regex.toString().replace("\"", "");
		}

		return "";
	}

	@Override
	public int getFirstAssignedValue() {
		return 0;
	}

	@Override
	public void full() {
		automata = null;
		regex = null;
		state = RegexState.FULL;
	}

}
