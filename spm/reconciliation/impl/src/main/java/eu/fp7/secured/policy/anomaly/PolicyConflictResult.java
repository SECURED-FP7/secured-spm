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
package eu.fp7.secured.policy.anomaly;


import eu.fp7.secured.policy.anomaly.utils.ConflictType;

// TODO: Auto-generated Javadoc
/**
 * The Class PolicyConflictResult.
 */
public class PolicyConflictResult {

	/** The conflict. */
	private ConflictType conflict;
	
	/** The sec level. */
	private int secLevel;
	
	/**
	 * Instantiates a new policy conflict result.
	 *
	 * @param conflict the conflict
	 * @param secLevel the sec level
	 */
	public PolicyConflictResult(ConflictType conflict, int secLevel){
		this.conflict = conflict;
		this.secLevel = secLevel;
	}

	/**
	 * Instantiates a new policy conflict result.
	 *
	 * @param conflict the conflict
	 */
	public PolicyConflictResult(ConflictType conflict){
		this.conflict = conflict;
		this.secLevel = -1;
	}
	

	/**
	 * Gets the conflict.
	 *
	 * @return the conflict
	 */
	public ConflictType getConflict() {
		return conflict;
	}
	
	/**
	 * Gets the sec level.
	 *
	 * @return the sec level
	 */
	public int getSecLevel(){
		return secLevel;
	}
}
