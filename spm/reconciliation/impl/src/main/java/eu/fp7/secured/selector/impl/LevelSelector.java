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

import javax.xml.bind.annotation.XmlEnumValue;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.Selector;


/**
 * The Class LevelSelector.
 */
public class LevelSelector implements ExactMatchSelector{
	
	/** The level_names. */
	public static String [] level_names={"child", "adolescent", "pgr", "universal"};
	
	/** The level. */
	private int level;

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getPointSet()
	 */
	@Override
	public BitSet getPointSet(){
		BitSet bs = new BitSet();
		if(level>=0)
			bs.set(level);
		return bs;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#getElementsNumber()
	 */
	@Override
	public int getElementsNumber(){
		return 1;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	@Override
	public void empty() {
		level = -1;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	@Override
	public Selector selectorClone() {
		LevelSelector levelSelector = new LevelSelector();
		try {
			levelSelector.addRange(level);
		} catch (InvalidRangeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return levelSelector;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		if(level == -1)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	@Override
	public boolean isFull() {
		if(level == -2)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if (((LevelSelector)s).level < level)
			level = ((LevelSelector)s).level;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (((LevelSelector)s).level > level)
			level = ((LevelSelector)s).level;
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
		if (((LevelSelector)s).level == level)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (((LevelSelector)s).level < level)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s)
			throws IllegalArgumentException {
		if (((LevelSelector)s).level <= level)
			return true;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	@Override
	public String toSimpleString() {
		return level_names[level];
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "["+level_names[level]+"/s]";
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	@Override
	public int getFirstAssignedValue() {
		// TODO Auto-generated method stub
		return level;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
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
		level = -2;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.ExactMatchSelector#addRange(java.lang.Object)
	 */
	public void addRange(Object Value) throws InvalidRangeException {
		int old_level = level;
		if(Value instanceof String){
			level = -100;
			for(int i=0; i<level_names.length; i++){
				if(level_names[i].equals(((String)Value).toLowerCase())){
					level = i;
				}
			}
		} else if (Value instanceof Integer){
			level = (Integer)Value;
		} else {
			throw new InvalidRangeException();
		}
		if(level==-100 || level>level_names.length){
			level = old_level;
			throw new InvalidRangeException();
		}
	}



}

	
	