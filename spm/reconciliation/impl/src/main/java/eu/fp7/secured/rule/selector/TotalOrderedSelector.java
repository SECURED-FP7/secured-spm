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

import java.util.List;

import eu.fp7.secured.exception.rule.InvalidRangeException;


/**
 * The Interface TotalOrderedSelector.
 */
public interface TotalOrderedSelector extends Selector{

	/**
	 * Adds the range.
	 *
	 * @param Value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(Object Value) throws InvalidRangeException;
	 
    /**
     * Adds the range.
     *
     * @param Start the start
     * @param End the end
     * @throws InvalidRangeException the invalid range exception
     */
	public void addRange(Object Start, Object End) throws InvalidRangeException;
	
	/**
	 * Gets the ranges.
	 *
	 * @return the ranges
	 */
	public Long[] getRanges();
	
}
