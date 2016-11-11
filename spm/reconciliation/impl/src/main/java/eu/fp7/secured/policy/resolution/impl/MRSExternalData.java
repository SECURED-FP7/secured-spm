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
package eu.fp7.secured.policy.resolution.impl;

/**
 * The Class MRSExternalData.
 */
public class MRSExternalData implements Cloneable{
	
	/** The internal priority. */
	protected int internalPriority;
	
	/** The set. */
	protected SetEnum set;
	
	/**
	 * Instantiates a new MRS external data.
	 *
	 * @param priority the priority
	 * @param set the set
	 */
	public MRSExternalData(int priority, SetEnum set){
		internalPriority = priority;
		this.set = set;
	}

	/**
	 * Gets the internal priority.
	 *
	 * @return the internal priority
	 */
	public int getInternalPriority() {
		return internalPriority;
	}

	/**
	 * Gets the sets the.
	 *
	 * @return the sets the
	 */
	public SetEnum getSet() {
		return set;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	public MRSExternalData clone(){
		
		return new MRSExternalData(internalPriority, set);
	
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		return this.set+" prio: "+internalPriority;
	}
	
	

	
}
