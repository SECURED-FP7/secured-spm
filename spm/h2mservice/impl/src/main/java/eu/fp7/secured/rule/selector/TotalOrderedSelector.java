package eu.fp7.secured.rule.selector;

import java.util.List;

import eu.fp7.secured.exception.rule.InvalidRangeException;


public interface TotalOrderedSelector extends Selector{

	/**
	 * Adds a Range into the Selector.
	 * 
	 * @param Value
	 * 			the punctiform range 
	 * @throws InvalidRangeException
	 */
	public void addRange(Object Value) throws InvalidRangeException;
	 
    /**
     *  Adds a Range into the Selector.
     *
     * @param Start End 
     * 		  points of the Range
     */
	public void addRange(Object Start, Object End) throws InvalidRangeException;
	
	public Long[] getRanges();
	
}
