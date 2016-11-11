package eu.fp7.secured.rule.selector;

import java.util.BitSet;

import eu.fp7.secured.exception.rule.InvalidRangeException;


public interface ExactMatchSelector extends Selector {

 /**
   * Adds a Range into the Selector.
   *
   * @param Value of the Range
   */	
	public void addRange(Object Value) throws InvalidRangeException;
	
	public BitSet getPointSet();
	
	public int getElementsNumber();

}
