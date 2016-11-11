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
 * The Class RegExpSelectorImpl.
 */
public abstract class RegExpSelectorImpl implements RegExpSelector {

	/** The full. */
	protected boolean full=false;
	
	/** The empty. */
	protected boolean empty=false;
	
	/** The automata. */
	protected Automaton automata;
	
	/** The regexp. */
	protected RegExp regexp;
	
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
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	public boolean isPoint(){
		if (automata!=null)
			return automata.isSingleton();
		
		return false;
	}
	
//	public RegExpSelectorImpl(){
//		selName="RegExp";
//		this.empty();
//	}
	
	/**
 * Sets the full.
 */
public void setFull(){
		full=true;
		empty=false;
		automata = Automaton.makeAnyString();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		full=false;
		empty=true;
		automata = Automaton.makeEmpty();
	}	
	
	/**
	 * Clone_non_empty_selector.
	 *
	 * @param s the s
	 */
	private void clone_non_empty_selector(RegExpSelectorImpl s){
		this.full=s.full;
		this.empty=s.empty;
		this.automata = s.automata.clone();	
		this.regexp = null;
	}

	
//	public boolean isPoint(){
//	if (automata!=null)
//		return automata.isSingleton();
//	
//	return false;
//}


	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#complement()
 */
@Override
	public void complement() {
		if(this.full)
			empty();
		else if(this.empty)
			setFull();
		else 
			automata = BasicOperations.complement(automata);
	}



	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if(((RegExpSelectorImpl)s).full)
			return;
		
		if(this.full)
			clone_non_empty_selector(((RegExpSelectorImpl)s));
		
		if (this.empty || ((RegExpSelectorImpl)s).empty)
			empty(); 

		
		automata = BasicOperations.intersection(automata, ((RegExpSelectorImpl) s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return this.empty;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if(this.full && ((RegExpSelectorImpl) s).full)
			return true;
		if(this.empty && ((RegExpSelectorImpl) s).empty)
			return true;
		
		return OtherOperations.equivalent(automata, ((RegExpSelectorImpl) s).automata);
	}

	 

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		if(this.empty || ((RegExpSelectorImpl) s).empty){
			//System.out.println("Sono qua e dico falso perchè this: "+this.empty+" - e altro: "+((RegExpSelectorImpl) s).empty);
			return false;
		}
		
		if(this.full || ((RegExpSelectorImpl) s).full){
			//System.out.println("Sono qua e dico vero");
			return true;
		}
			
		return OtherOperations.intersecting(automata, ((RegExpSelectorImpl) s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull())
			return false;
		
		if (s.isFull())
			return true;
		
		return OtherOperations.subsetNotEquivalent(automata, ((RegExpSelectorImpl) s).automata);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override 
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		//TODO: controllare significato logico, empty è sottoinsieme? secondo me si
		if(this.empty)
			return true;
		if(((RegExpSelectorImpl) s).empty) // &&!this.empty
			return false;
		if(((RegExpSelectorImpl) s).full) //qui nè l'uno nè l'altro sono empty
			return true;
		
		return BasicOperations.subsetOf(automata, ((RegExpSelectorImpl) s).automata);
	}

	 


//	@Override 
//	public void setMinus(Selector s) throws IllegalArgumentException {
//		if(this.empty || ((RegExpSelectorImpl) s).empty)
//			return;
//		if(((RegExpSelectorImpl) s).full)
//			empty();
//		
//		automata = BasicOperations.minus(automata, ((RegExpSelectorImpl) s).automata);
//	}

	 
	 
	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
 */
@Override
	public void union(Selector s) throws IllegalArgumentException {
		if(this.full || ((RegExpSelectorImpl) s).empty)
			return;
		if(((RegExpSelectorImpl) s).full)
			this.setFull();
		if(this.empty)
			clone_non_empty_selector(((RegExpSelectorImpl) s));
		
		automata = BasicOperations.union(automata, ((RegExpSelectorImpl) s).automata);
		//automata.determinize();
	}

	 


	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	public String toSimpleString() {
		return "to implement";
	}
		
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		return full;
	}

	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString(){
		if (automata!= null)
			return automata.toString();
		return "Empty";
	}
	
	/**
	 * To reg exp.
	 *
	 * @return the string
	 */
	public String toRegExp(){
		return OtherOperations.toRegExp(automata);
	}
	
}