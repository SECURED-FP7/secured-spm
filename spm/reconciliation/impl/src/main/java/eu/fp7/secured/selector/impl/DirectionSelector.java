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


import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;


/**
 * The Class DirectionSelector.
 */
public class DirectionSelector extends ExactMatchSelectorImpl {
	
	/**
	 * Instantiates a new direction selector.
	 */
	public DirectionSelector(){
		this.ranges = new RealBitSet(MAX_VALUE+1);
	}

	/** The direction. */
	public static String [] direction={"IN", "OUT"};
	
	/** The min value. */
	private static int MAX_VALUE=1, MIN_VALUE=0;

	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String)Value);
		else if (Value instanceof java.lang.Integer)
			addRange((Integer)Value);
		else throw new InvalidRangeException();
	}
	
	/**
	 * Adds the range.
	 *
	 * @param value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String value) throws InvalidRangeException{
		boolean stop = false;
		int i=0;
		
		if (value.equalsIgnoreCase("any")){
			for(i=0;i<=MAX_VALUE;i++)
				ranges.set(i);
			return;
		}
		
		for (i=0;i<direction.length && !stop;i++) {
			if (value.equalsIgnoreCase(direction[i]))
				stop = true;
		}
		if (stop) {
			addRange(--i);
			
		} else {
			int val = Integer.parseInt(value);
			
			if (val<=MAX_VALUE && val>=MIN_VALUE)
				addRange(val);
			else throw new IllegalArgumentException();
		}

	}
	
	/**
	 * Adds the range.
	 *
	 * @param value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(int value) throws InvalidRangeException{
		if (value<MIN_VALUE || value>MAX_VALUE){
			System.out.println(value);
			throw new InvalidRangeException("Value: "+value);
		}
		
		ranges.set(value);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	public DirectionSelector selectorClone() {
		DirectionSelector pid = new DirectionSelector();
		pid.ranges = (RealBitSet)ranges.clone(); 
		return pid;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";
		
		//int bitSet=0;
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
				str = str + "["+direction[i]+"] ";
		 }
		return str;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	public String toSimpleString() {
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
				str = str + direction[i];
				if(ranges.nextSetBit(i+1) >= 0)
					str = str + ";";
		 }
		return str;
	}


	/**
	 * Gets the max value.
	 *
	 * @return the max value
	 */
	public static int getMAX_VALUE() {
		return MAX_VALUE;
	}

	/**
	 * Gets the min value.
	 *
	 * @return the min value
	 */
	public static int getMIN_VALUE() {
		return MIN_VALUE;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getElementsNumber()
	 */
	@Override
	public int getElementsNumber() {
		return MAX_VALUE+1;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.selector.impl.ExactMatchSelectorImpl#full()
	 */
	@Override
	public void full() {
		ranges.set(0);
		ranges.set(1);
	}
}
