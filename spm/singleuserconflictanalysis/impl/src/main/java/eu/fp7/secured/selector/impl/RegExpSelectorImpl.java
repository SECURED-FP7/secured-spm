package eu.fp7.secured.selector.impl;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.BasicOperations;
import dk.brics.automaton.OtherOperations;
import dk.brics.automaton.RegExp;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;

public abstract class RegExpSelectorImpl implements RegExpSelector {

	protected boolean full=false;
	protected boolean empty=false;
	
	protected Automaton automata;
	protected RegExp regexp;
	
	public Automaton getAutomaton(){
		if (automata!=null)
			return automata.clone();
		return new Automaton();
	}
	
	public boolean isPoint(){
		if (automata!=null)
			return automata.isSingleton();
		
		return false;
	}
	
//	public RegExpSelectorImpl(){
//		selName="RegExp";
//		this.empty();
//	}
	
	public void setFull(){
		full=true;
		empty=false;
		automata = Automaton.makeAnyString();
	}
	
	@Override
	public void empty() {
		full=false;
		empty=true;
		automata = Automaton.makeEmpty();
	}	
	
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


	@Override
	public void complement() {
		if(this.full)
			empty();
		else if(this.empty)
			setFull();
		else 
			automata = BasicOperations.complement(automata);
	}



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

	@Override
	public boolean isEmpty() {
		return this.empty;
	}

	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if(this.full && ((RegExpSelectorImpl) s).full)
			return true;
		if(this.empty && ((RegExpSelectorImpl) s).empty)
			return true;
		
		return OtherOperations.equivalent(automata, ((RegExpSelectorImpl) s).automata);
	}

	 

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

	 


	public String toSimpleString() {
		return "to implement";
	}
		
	@Override
	public boolean isFull() {
		return full;
	}

	
	@Override
	public String toString(){
		if (automata!= null)
			return automata.toString();
		return "Empty";
	}
	
	public String toRegExp(){
		return OtherOperations.toRegExp(automata);
	}
	
}