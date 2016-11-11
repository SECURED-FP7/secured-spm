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

import eu.fp7.secured.rule.selector.RegExpSelector;

/**
 * The Class RegexBlock.
 */
public class RegexBlock implements Block{
	
	/** The s. */
	RegExpSelector s;
	
	/** The bs. */
	BitSet bs;
	
	/**
	 * Instantiates a new regex block.
	 *
	 * @param s the s
	 */
	public RegexBlock(RegExpSelector s){
		this.s=s;
		bs = new BitSet();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.Block#getBs()
	 */
	@Override
	public BitSet getBs() {
		return bs;
	}
	
	/**
	 * Sets the bs.
	 *
	 * @param bs the new bs
	 */
	public void setBs(BitSet bs) {
		this.bs=bs;
	}
	
	/**
	 * Gets the selector.
	 *
	 * @return the selector
	 */
	public RegExpSelector getSelector(){
		return s;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return s.toString();
	}
}
