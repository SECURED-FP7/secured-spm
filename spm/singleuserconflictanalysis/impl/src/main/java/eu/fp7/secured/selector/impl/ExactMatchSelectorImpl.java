package eu.fp7.secured.selector.impl;

import eu.fp7.secured.policy.utils.RealBitSet;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;


public abstract class ExactMatchSelectorImpl implements ExactMatchSelector {
	
	protected RealBitSet ranges;
	
	//private SelectorFactory<T> factory;
	
	public boolean isPoint(){
		if (ranges!=null)
			if (ranges.cardinality()==1)
				return true;
		
		return false;
	}
	
	public int getFirstAssignedValue(){
		return ranges.nextSetBit(0);
	}
	
	
	public RealBitSet getPointSet(){
		return ranges;
	}
	
	protected RealBitSet getRealBitSet(){
		return ranges;
	}
	
//	public SelectorFactory<T> getFactory() {
//		return factory;
//	}
	/**
	  * Calculates the complement of the specified Selector.

	  */
	public void complement() {
		ranges.flip(0, ranges.size()-1);
			
	}

	public void empty() {
		ranges.clear();		
	}

	/**
	 * Calculates intersection between this Selector and Selector s
	 * 
	 * @param s 
	 * 		
	 * 
	 * @throws polito.conflicts.range.IllegalArgumentException
	 */
	public void intersection(Selector s) throws IllegalArgumentException {		
		ranges.and(((ExactMatchSelector) s).getPointSet());		
	}

	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty();
	}
	
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty() && ranges.cardinality()< ((ExactMatchSelector) s).getPointSet().cardinality();
	}

/*	- a is contained (ma non uguale) b
	a.andNot(b)
	a.isEmpty() && b.cardinality() == a.cardinality()*/
	
	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
//		ExactMatchSelector ems = (ExactMatchSelector) s;
		
		RealBitSet rclone = (RealBitSet) ranges.clone();
		rclone.andNot(((ExactMatchSelector) s).getPointSet());
		
		return rclone.isEmpty() && ranges.cardinality() == ((ExactMatchSelector) s).getPointSet().cardinality();
		
	}

	public boolean isFull() {
		ranges.flip(0, ranges.size());
		
		boolean res = ranges.isEmpty();
		ranges.flip(0, ranges.size());
		
		return res;
	}

	public boolean isIntersecting(Selector  s) throws IllegalArgumentException {
		//ExactMatchSelector ems = (ExactMatchSelector) s;
		return ranges.intersects(((ExactMatchSelector) s).getPointSet());
	}

	/**
	  * Calculates the set minus between this Selector and Selector s.
	  *
	  * @param	s
	  * 	 Selector
	  * @throws polito.conflicts.range.IllegalArgumentException
	  */
	public void setMinus(Selector s) throws IllegalArgumentException {
		ranges.andNot(((ExactMatchSelector) s).getPointSet());	
	}

	/**
	 * Calculates union between this Selector and Selector s
	 * 
	 * @param s
	 * 		Selector
	 * @throws polito.conflicts.range.IllegalArgumentException
	 */	
	public void union(Selector s) throws IllegalArgumentException {
		ranges.or(((ExactMatchSelector) s).getPointSet());
	}
	


	public long length(){
		return ranges.cardinality(); 
	}
	
	
	@Override
	public void full() {
		ranges.set(0, ranges.size(), true);
	}
	
	
}
