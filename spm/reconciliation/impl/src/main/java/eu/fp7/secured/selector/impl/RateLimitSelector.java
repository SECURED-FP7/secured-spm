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

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class RateLimitSelector.
 */
public class RateLimitSelector implements Selector{
	
	/** The rate limit. */
	private int rateLimit;

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		rateLimit = 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public Selector selectorClone() {
		RateLimitSelector rateLimitSelector = new RateLimitSelector();
		try {
			rateLimitSelector.addRange(rateLimit);
		} catch (InvalidRangeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return rateLimitSelector;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		if(rateLimit == 0)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		if(rateLimit == -1)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit < rateLimit)
			rateLimit = ((RateLimitSelector)s).rateLimit;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit > rateLimit)
			rateLimit = ((RateLimitSelector)s).rateLimit;
	}

	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	@Override
	public void complement() {
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		// TODO Auto-generated method stub
		return true;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit == rateLimit)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit < rateLimit)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s)
			throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit <= rateLimit)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		return rateLimit+"/s";
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "["+rateLimit+"/s]";
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	@Override
	public int getFirstAssignedValue() {
		// TODO Auto-generated method stub
		return rateLimit;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
		// TODO Auto-generated method stub
		return 1;
	}


	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	@Override
	public boolean isPoint() {
		return true;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		rateLimit = -1;
	}

	/**
	 * Adds the range.
	 *
	 * @param Value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(Object Value) throws InvalidRangeException {
		rateLimit = (Integer)Value;
	}



}
