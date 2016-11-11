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
 * The Class RealBitSet.
 */
@SuppressWarnings("serial")
public class RealBitSet extends BitSet implements Cloneable{
	
	/** The real size. */
	private int realSize;

	/**
	 * Instantiates a new real bit set.
	 */
	public RealBitSet() {
	}

	/**
	 * Instantiates a new real bit set.
	 *
	 * @param nbits the nbits
	 */
	public RealBitSet(int nbits) {
		super(nbits);
		realSize = nbits;
		
	}

	/* (non-Javadoc)
	 * @see java.util.BitSet#size()
	 */
	@Override
	public int size() {	
		return realSize;
	}

}
