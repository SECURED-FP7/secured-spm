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

import eu.fp7.secured.policy.utils.RealBitSet;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;


/**
 * The Class ExactMatchSelectorImpl.
 */
public abstract class ExactMatchSelectorImpl implements ExactMatchSelector {
	
	/** The ranges. */
	protected RealBitSet ranges;
	
	//private SelectorFactory<T> factory;
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	public boolean isPoint(){
		if (ranges!=null)
			if (ranges.cardinality()==1)
				return true;
		
		return false;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	public int getFirstAssignedValue(){
		return ranges.nextSetBit(0);
	}
	
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getPointSet()
	 */
	public RealBitSet getPointSet(){
		return ranges;
	}
	
	/**
	 * Gets the real bit set.
	 *
	 * @return the real bit set
	 */
	protected RealBitSet getRealBitSet(){
		return ranges;
	}
	
//	public SelectorFactory<T> getFactory() {
//		return factory;
//	}
	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#complement()
 */
	public void complement() {
		ranges.flip(0, ranges.size()-1);
			
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	public void empty() {
		ranges.clear();		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	public void intersection(Selector s) throws IllegalArgumentException {		
		ranges.and(((ExactMatchSelector) s).getPointSet());		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty() && ranges.cardinality()< ((ExactMatchSelector) s).getPointSet().cardinality();
	}

/*	- a is contained (ma non uguale) b
	a.andNot(b)
	a.isEmpty() && b.cardinality() == a.cardinality()*/
	
	/* (non-Javadoc)
 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
 */
public boolean isEmpty() {
		return ranges.isEmpty();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
//		ExactMatchSelector ems = (ExactMatchSelector) s;
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty() && ranges.cardinality() == ((ExactMatchSelector) s).getPointSet().cardinality();
		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	public boolean isFull() {
		ranges.flip(0, ranges.size());
		
		boolean res = ranges.isEmpty();
		ranges.flip(0, ranges.size());
		
		return res;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isIntersecting(Selector  s) throws IllegalArgumentException {
		//ExactMatchSelector ems = (ExactMatchSelector) s;
		return ranges.intersects(((ExactMatchSelector) s).getPointSet());
	}

	/**
	 * Sets the minus.
	 *
	 * @param s the new minus
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public void setMinus(Selector s) throws IllegalArgumentException {
		ranges.andNot(((ExactMatchSelector) s).getPointSet());	
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */	
	public void union(Selector s) throws IllegalArgumentException {
		ranges.or(((ExactMatchSelector) s).getPointSet());
	}
	


	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	public long length(){
		return ranges.cardinality(); 
	}
	
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		ranges.set(0, ranges.size(), true);
	}
	
	
}
