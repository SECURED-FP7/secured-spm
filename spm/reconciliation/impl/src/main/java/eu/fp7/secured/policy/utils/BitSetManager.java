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
package eu.fp7.secured.policy.utils;

import java.util.BitSet;

/**
 * The Class BitSetManager.
 */
public class BitSetManager {
	
	/** The mask. */
	BitSet mask;
	
	/** The starting bit. */
	int startingBit;
	
	/** The next_index. */
	int next_index;
	
	/**
	 * Instantiates a new bit set manager.
	 */
	public BitSetManager()
	{
		next_index=1;
		startingBit = 1;
		mask = new IndexingBitSet();
	}
	
	/**
	 * Instantiates a new bit set manager.
	 *
	 * @param startingBit the starting bit
	 */
	public BitSetManager(int startingBit)
	{
		next_index=startingBit;
		mask = new IndexingBitSet();
	}

	
	/**
	 * Clear.
	 */
	public void clear(){
		next_index = 1;
		mask.clear();
	}
	
	/**
	 * Gets the index.
	 *
	 * @return the index
	 */
	public IndexingBitSet getIndex()
	{
		IndexingBitSet bs = new IndexingBitSet();
		bs.set(next_index);
		mask.set(next_index);
		next_index = mask.nextClearBit(next_index);
		return bs;
	}
	
	/**
	 * Release index.
	 *
	 * @param bs the bs
	 */
	public void releaseIndex(IndexingBitSet bs)
	{
		int pos = bs.nextSetBit(startingBit -1);
		if(pos<next_index)
		{
			next_index = pos;
		}
		mask.clear(pos);
	}
	
	/**
	 * Gets the max assigned bit.
	 *
	 * @return the max assigned bit
	 */
	public int getMaxAssignedBit(){
		return mask.length()-1;
	}
	
	/**
	 * Assigned bits.
	 *
	 * @return the int
	 */
	public int assignedBits(){
		return mask.cardinality();
	}

}
