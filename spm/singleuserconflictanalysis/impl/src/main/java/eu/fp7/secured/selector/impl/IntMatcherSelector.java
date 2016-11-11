package eu.fp7.secured.selector.impl;

import java.util.BitSet;
import java.util.HashSet;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;


public class IntMatcherSelector implements ExactMatchSelector {

	private HashSet<Integer> values;
	
	boolean negated=false;

	
	
	public IntMatcherSelector(){
		values = new HashSet<Integer>();
	}
	
	public void addRange(Integer value) throws InvalidRangeException {
		if (!values.contains(value))
			values.add(value);
	}
	
	public void addRange(String Value) throws InvalidRangeException {
		Integer value = Integer.parseInt(Value);
		
		if (!values.contains(value))
			values.add(value);
	}
	
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String) Value);
		else if (Value instanceof java.lang.Integer)
			addRange((Integer) Value);
		else throw new InvalidRangeException();
		
	}

	@Override
	public BitSet getPointSet() {
		return null;
	}

	@Override
	public void complement() {
		negated = !negated;
	}

	@Override
	public void empty() {
		values.clear();
	}

	

	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
			HashSet<Integer> result = new HashSet<Integer>();
		
			if (this.negated == ((IntMatcherSelector)s).negated){
				HashSet<Integer> out=values, in=((IntMatcherSelector)s).values;
				
				if (values.size()<((IntMatcherSelector)s).values.size()){
					out = ((IntMatcherSelector)s).values;
					in = values;
				}
				
				for (Integer s1 : out)
					if (in.contains(s1)) //verificare se funziona
						result.add(s1);
						
			}
			
			//values.clear();
			values = result;
			
			//TODO valutare comportamento se sono negati
			
		
	}

	@Override
	public boolean isEmpty() {
		return values.isEmpty();
	}

	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((IntMatcherSelector)s).negated && values.size()==((IntMatcherSelector)s).values.size()){
			
			for (Integer s1 : values){
				found = false;
				if (((IntMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	@Override
	public boolean isFull() {
		System.err.println("Not allowe dfor this selector");
		return false;
	}

	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		
		
		if (this.negated == ((IntMatcherSelector)s).negated){
			HashSet<Integer> out=values, in=((IntMatcherSelector)s).values;
			
			if (values.size()<((IntMatcherSelector)s).values.size()){
				out = ((IntMatcherSelector)s).values;
				in = values;
			}
			
			for (Integer s1 : out)
				if (in.contains(s1)) //verificare se funziona
					return true;
					
		}
		
		return false;
	}

	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((IntMatcherSelector)s).negated && values.size()<((IntMatcherSelector)s).values.size()){
			
			for (Integer s1 : values){
				found = false;
				if (((IntMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	@Override
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((IntMatcherSelector)s).negated && values.size()<=((IntMatcherSelector)s).values.size()){
			
			for (Integer s1 : values){
				found = false;
				if (((IntMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	@Override
	public long length() {
		return values.size();
	}

	@Override
	public IntMatcherSelector selectorClone() {
		IntMatcherSelector sm = new IntMatcherSelector();
		
		for (Integer s : values)
			sm.values.add(s);
		
		return sm;
	}

//	@Override
//	public void setMinus(Selector s) throws IllegalArgumentException {
//		if (this.negated == ((IntMatcherSelector)s).negated)
//			for (Integer s1 : ((IntMatcherSelector)s).values)
//				values.remove(s1);
//		
//		if (!this.label.equalsIgnoreCase(s.getLabel()))
//			if(!s.getLabel().equals(""))
//				label = label + " || "+s.getLabel();
//	}

	@Override
	public String toSimpleString() {
		StringBuffer sb = new StringBuffer();
		
		for (Integer s : values){
			sb.append(s);
			sb.append(";");
		}
		
		return sb.toString();
	}
	

	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (this.negated == ((IntMatcherSelector)s).negated)
			for (Integer s1 : ((IntMatcherSelector)s).values)
				values.remove(s1);
		
		
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		
		
		for (Integer s : values){
			sb.append(s);
			sb.append("; ");
		}
		
		return sb.toString();
	}

	@Override
	public int getElementsNumber() {
		return -1;
	}
	
	@Override
	public int getFirstAssignedValue() {
		if (values!=null)
			if(values.size()>0)
				return values.iterator().next();
		
		return 0;
	}

	@Override
	public boolean isPoint() {
		if (values.size()==1)
			return true;
		
		return false;
	}

	@Override
	public void full() {
	}
}
