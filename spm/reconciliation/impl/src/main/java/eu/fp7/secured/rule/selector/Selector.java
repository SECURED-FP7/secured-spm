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
package eu.fp7.secured.rule.selector;


/**
 * The Interface Selector.
 */
public interface Selector {

	/**
	 * Empty.
	 */
	public void empty();
	
	/**
	 * Selector clone.
	 *
	 * @return the selector
	 */
	public Selector selectorClone();

	/**
	 * Checks if is empty.
	 *
	 * @return true, if is empty
	 */
	public boolean isEmpty();
	
	/**
	 * Checks if is full.
	 *
	 * @return true, if is full
	 */
	public boolean isFull();
	
  /**
   * Intersection.
   *
   * @param s the s
   * @throws IllegalArgumentException the illegal argument exception
   */
	public void intersection(Selector s) throws IllegalArgumentException;
	
   /**
    * Union.
    *
    * @param s the s
    * @throws IllegalArgumentException the illegal argument exception
    */	
	public void union(Selector s) throws IllegalArgumentException;

	/**
	 * Complement.
	 */	
	public void complement();

	/**
	 * Checks if is intersecting.
	 *
	 * @param s the s
	 * @return true, if is intersecting
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public boolean isIntersecting(Selector s) throws IllegalArgumentException;
	
	/**
	 * Checks if is equivalent.
	 *
	 * @param s the s
	 * @return true, if is equivalent
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public boolean isEquivalent(Selector s) throws IllegalArgumentException;
	

	/**
	 * Checks if is subset.
	 *
	 * @param s the s
	 * @return true, if is subset
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public boolean isSubset(Selector s) throws IllegalArgumentException;	

	/**
	 * Checks if is subset or equivalent.
	 *
	 * @param s the s
	 * @return true, if is subset or equivalent
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException;	
	
	/**
	 * To simple string.
	 *
	 * @return the string
	 */
	public String toSimpleString();
	
	/**
	 * Gets the first assigned value.
	 *
	 * @return the first assigned value
	 */
	public int getFirstAssignedValue();

	/**
	 * Length.
	 *
	 * @return the long
	 */
	public long length();
	
	/**
	 * Checks if is point.
	 *
	 * @return true, if is point
	 */
	public boolean isPoint();

	/**
	 * Full.
	 */
	public void full();
}
