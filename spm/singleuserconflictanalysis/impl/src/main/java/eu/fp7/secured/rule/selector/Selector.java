package eu.fp7.secured.rule.selector;


public interface Selector {

	/**
	 * Deletes every Range contained in the Selector
	 * 
	 */
	public void empty();
	
	/**
	 * 
	 * @return Selector's clone
	 * @throws Exception
	 */
	public Selector selectorClone();

	/**
	 * 
	 * @return True if the Selector is empty else returns false
	 */
	public boolean isEmpty();
	
	/**
	 * 
	 * @return True if the Selector contains every element
	 */
	public boolean isFull();
	
  /**
    * Calculates the intersection with another Selector.
    *
    * @param  s - Selector	
    * @throws Exception
    */
	public void intersection(Selector s) throws IllegalArgumentException;
	
   /**
    * Calculates the union with another Selector.
    *
    * @param	s Selector
    */	
	public void union(Selector s) throws IllegalArgumentException;

	/**
	  * Transforms current Selector in his complement.
	  *
	  */	
	public void complement();

	/**
	 * 
	 * @param s Selector
	 * @return True if the Selector param is intersecting with current Selector
	 */
	public boolean isIntersecting(Selector s) throws IllegalArgumentException;
	
	/**
	 * 
	 * @param s Selector 
	 * @return True if the Selector param is the same as the current Selector
	 */
	public boolean isEquivalent(Selector s) throws IllegalArgumentException;
	

	/**
	 * 
	 * @param s Selector 
	 * @return True if the current Selector is a subset, not equivalent, of the param Selector
	 */
	public boolean isSubset(Selector s) throws IllegalArgumentException;	

	/**
	 * 
	 * @param s Selector 
	 * @return True if the current Selector is equivalent or a subset of the param Selector
	 */
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException;	
	
	/**
	 * 
	 * @return A formatted string representing this Selector
	 */
	public String toSimpleString();
	
	/**
	 * 
	 * @return
	 */
	public int getFirstAssignedValue();

	public long length();
	
	public boolean isPoint();

	public void full();
}
