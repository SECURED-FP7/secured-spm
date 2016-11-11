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
 * The Class EthernetPrioritySelector.
 */
public class EthernetPrioritySelector extends ExactMatchSelectorImpl {

	/** The String value. */
	private static String [] StringValue={"Best Effort","Background","Spare","Excellent Effort","Controlled Load",
		"Video < 100 ms latency and jitter","Voice < 10 ms latency and jitter","Network Control"};
	
	/** The Element number. */
	private int ElementNumber=StringValue.length;
	
	/**
	 * Instantiates a new ethernet priority selector.
	 */
	public EthernetPrioritySelector(){
		ranges = new RealBitSet(ElementNumber);
	}
	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	public void addRange(Object Value) throws InvalidRangeException {		
	}
	
	/**
	 * Adds the range.
	 *
	 * @param i the i
	 * @throws InvalidRangeException the invalid range exception
	 */
	/*
	 * (non-Javadoc)
	 * @see org.polito.ruleManagement.selector.SetBasedSelector#addRange(java.lang.Object)
	 */
	public void addRange(int i) throws InvalidRangeException{
		if (i<0 || i>= ElementNumber)
			throw new InvalidRangeException("Value: "+i);
		ranges.set(i);
	}
	
	/**
	 * Adds the range.
	 *
	 * @param Value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	/*
	 * (non-Javadoc)
	 * @see org.polito.ruleManagement.selector.SetBasedSelector#addRange(java.lang.Object)
	 */
	public void addRange(String Value) throws InvalidRangeException {
		int value=0;
		boolean found=false;
		
		for (;value<StringValue.length && !found;value++)
				if (StringValue[value].equals(Value))
					found=true;	
		if (found)
			ranges.set(value);
		else throw new InvalidRangeException("Value: "+value);
	}

	/*
	 * (non-Javadoc)
	 * @see org.polito.ruleManagement.selector.Selector#selectorClone()
	 */
	public EthernetPrioritySelector selectorClone() {
		EthernetPrioritySelector pid = new EthernetPrioritySelector();
		pid.ranges = (RealBitSet)ranges.clone(); 
		return pid;
	}
	
	/*
	 * (non-Javadoc)
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
			str = str + "["+StringValue[i]+"] ";
		}
		return str;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getElementsNumber()
	 */
	public int getElementsNumber() {
		return ElementNumber;
	}

	/**
	 * Gets the element number.
	 *
	 * @return the element number
	 */
	public static int getElementNumber() {
		return StringValue.length;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		String str="";
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
			str = str +StringValue[i]+";";
		}
		return str;
	}

}
