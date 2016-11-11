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
import java.util.HashMap;
import java.util.List;

import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Interface BlockList.
 */
public interface BlockList {

	/**
	 * Insert.
	 *
	 * @param s the s
	 * @param index the index
	 * @return true, if successful
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	public boolean insert(Selector s, int index) throws UnsupportedSelectorException;
	
	/**
	 * Gets the blocks.
	 *
	 * @return the blocks
	 */
	public List<Block> getBlocks();
	
	/**
	 * Gets the blocks as selectors.
	 *
	 * @return the blocks as selectors
	 */
	public List<Selector> getBlocksAsSelectors();
	
	/**
	 * Gets the blocks and bit sets.
	 *
	 * @return the blocks and bit sets
	 */
	public HashMap<Selector, BitSet> getBlocksAndBitSets();
	
	/**
	 * At least one label.
	 *
	 * @return true, if successful
	 */
	public boolean atLeastOneLabel();
	
	/**
	 * Gets the bit set.
	 *
	 * @param index the index
	 * @return the bit set
	 */
	public BitSet getBitSet(int index);
	
}
