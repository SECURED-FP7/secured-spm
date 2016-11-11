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
import java.util.HashSet;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;


/**
 * The Class StringMatcherSelector.
 */
public class StringMatcherSelector implements ExactMatchSelector {

	/** The values. */
	private HashSet<String> values;
	
	/** The negated. */
	boolean negated=false;

	/**
	 * Instantiates a new string matcher selector.
	 */
	public StringMatcherSelector(){
		values = new HashSet<String>();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String)Value);
		else throw new InvalidRangeException();
		
	}
	
	/**
	 * Adds the range.
	 *
	 * @param Value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String Value) throws InvalidRangeException {
		values.add(Value);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getPointSet()
	 */
	@Override
	public BitSet getPointSet() {
		return null;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	@Override
	public void complement() {
		negated = !negated;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		values.clear();
		
	}



	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		
			HashSet<String> result = new HashSet<String>();
		
			if (this.negated == ((StringMatcherSelector)s).negated){
				HashSet<String> out=values, in=((StringMatcherSelector)s).values;
				
				if (values.size()<((StringMatcherSelector)s).values.size()){
					out = ((StringMatcherSelector)s).values;
					in = values;
				}
				
				for (String s1 : out)
					if (in.contains(s1)) //verificare se funziona
						result.add(s1);
						
			}
			
			//values.clear();
			values = result;
			
			//TODO valutare comportamento se sono negati
		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return values.isEmpty();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((StringMatcherSelector)s).negated && values.size()==((StringMatcherSelector)s).values.size()){
			
			for (String s1 : values){
				found = false;
				if (((StringMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		System.err.println("Not allowed for this selector");
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		
		
		if (this.negated == ((StringMatcherSelector)s).negated){
			HashSet<String> out=values, in=((StringMatcherSelector)s).values;
			
			if (values.size()<((StringMatcherSelector)s).values.size()){
				out = ((StringMatcherSelector)s).values;
				in = values;
			}
			
			for (String s1 : out)
				if (in.contains(s1)) //verificare se funziona
					return true;
					
		}
		
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((StringMatcherSelector)s).negated && values.size()<((StringMatcherSelector)s).values.size()){
			
			for (String s1 : values){
				found = false;
				if (((StringMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		boolean found=false;
		if (this.negated == ((StringMatcherSelector)s).negated && values.size()<=((StringMatcherSelector)s).values.size()){
			
			for (String s1 : values){
				found = false;
				if (((StringMatcherSelector)s).values.contains(s1)) //verificare se funziona
					found = true;
				if (!found)
					break;
			}
					
		}
		return found;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
		return values.size();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public StringMatcherSelector selectorClone() {
		StringMatcherSelector sm = new StringMatcherSelector();
		
		for (String s : values)
			sm.values.add(s);
		
		return sm;
	}

//	@Override
//	public void setMinus(Selector s) throws IllegalArgumentException {
//		if (this.negated == ((StringMatcherSelector)s).negated)
//			for (String s1 : ((StringMatcherSelector)s).values)
//				values.remove(s1);
//	}

	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
 */
@Override
	public String toSimpleString() {
		StringBuffer sb = new StringBuffer();
		
		for (String s : values){
			sb.append(s);
			sb.append(";");
		}
		
		return sb.toString();
	}
	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (this.negated == ((StringMatcherSelector)s).negated)
			for (String s1 : ((StringMatcherSelector)s).values)
				values.remove(s1);
		
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		
		
		for (String s : values){
			sb.append(s);
			sb.append("; ");
		}
		
		return sb.toString();
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
	public int getFirstAssignedValue() {
		if (values!=null)
			if(values.size()>0)
				return values.iterator().next().hashCode();
		
		return 0;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	@Override
	public boolean isPoint() {
		if (values.size()==1)
			return true;
		
		return false;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		// TODO Auto-generated method stub
		
	}

}
