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
 * The Class WeekdaySelector.
 */
public class WeekdaySelector extends ExactMatchSelectorImpl {

	/** The days. */
	public static String [] days={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	
	/** The min value. */
	private static int MAX_VALUE=6, MIN_VALUE=0;
	
	/**
	 * Instantiates a new weekday selector.
	 */
	public WeekdaySelector(){
		//TODO
		//factory = ProtocolIDSelectorFactory.getInstance();
		ranges = new RealBitSet(MAX_VALUE+1);
		//System.err.println(ranges.size());
		
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String)Value);
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
		for (i=0;i<=MAX_VALUE && !stop;i++) {
			if (value.equalsIgnoreCase(days[i]))
				stop = true;
		}
		if (stop) {
			ranges.set(--i);
			
		} else throw new IllegalArgumentException();
	}
	
	/**
	 * Adds the range.
	 *
	 * @param value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(int value) throws InvalidRangeException{
//		boolean stop = false;

		
		if (MIN_VALUE <= value || value>MAX_VALUE) {
			ranges.set(value);
			
		} else throw new IllegalArgumentException();
	}


	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public WeekdaySelector selectorClone() {
		WeekdaySelector pid = new WeekdaySelector();
		pid.ranges = (RealBitSet)ranges.clone(); 
		return pid;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";
		
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)){ 
				str = str + days[i];
				if(ranges.nextSetBit(i+1) >= 0)
					str = str + ",";
		}
		
		 
		return str;
	}


	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";
		
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) 
				str = str + "["+days[i]+"] ";
		 
		return str;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getElementsNumber()
	 */
	@Override
	public int getElementsNumber() {
		return days.length;
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
}
