package eu.fp7.secured.selector.impl;

import eu.fp7.secured.rule.selector.TotalOrderedSelector;

public abstract class TotalOrderedSelectorImpl implements TotalOrderedSelector {


	
//	public SelectorFactory<T> getFactory() {
//		return factory;
//	}
	
	/**
	  * Calculates the complement of Selector s.
	  *
	  * @param	s Selector
	  * @return Complement Selector
	  * @throws Exception
	  */
/*	public static Selector complement(Selector s) throws Exception
	{
		Selector s1 = s.selectorClone();
       s1.complement(); 
       return s1;		
	}
*/	
	/**
	  * Calculates the set minus between Selector s1 and Selector s2.
	  *
	  * @param	s1 Selector, s2 Selector
	  * @return Selector - result of set minus between s1 and s2 
	  * @throws polito.conflicts.range.IllegalArgumentException
	  */	
/*	public static Selector setMinus(Selector s1, Selector s2) throws Exception
	{
		if(!s1.getClass().equals(s2.getClass()))
		{
			throw new IllegalArgumentException(s1.getClass() + "incompatible with " + s2.getClass());
		}
		Selector s = s1.selectorClone();
      s.setMinus(s2); 
      return s;		
	}
*/	
	/**
	 * Calculates union between Selector s1 and Selector s2
	 * 
	 * @param s1 - Selector
	 * @param s2 - Selector
	 * @return Selector - result of union between s1 and s2 
	 * @throws polito.conflicts.range.IllegalArgumentException
	 */
/*	public static Selector union(Selector s1, Selector s2) throws Exception
	{
		if (!s1.getClass().equals(s2.getClass()))
		{
			throw new IllegalArgumentException(s1.getClass() + "incompatible with " + s2.getClass());
		}
		Selector s = s1.selectorClone();
		s.union(s2);
		return s;
	}
*/	
	/**
	 * Calculates intersection between Selector s1 and Selector s2
	 * 
	 * @param s1 - Selector
	 * @param s2 - Selector
	 * @return Selector - result of intersection between s1 and s2 
	 * @throws polito.conflicts.range.IllegalArgumentException
	 */
/*	public static Selector intersection(Selector s1, Selector s2) throws Exception
	{
		if (!s1.getClass().equals(s2.getClass()))
		{
			throw new IllegalArgumentException(s1.getClass() + "incompatible with " + s2.getClass());
		}
		Selector s = s1.selectorClone();
		s.intersection(s2);
		return s;

	}
*/
}
