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
package eu.fp7.secured.exception.policy;


/**
 * The Class NotInSemiLatticeException.
 */

public class NotInSemiLatticeException extends Exception {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -8847019385112414653L;

	/**
	 * Instantiates a new not in semi lattice exception.
	 */
	public NotInSemiLatticeException()
	{}
	
	/**
	 * Instantiates a new not in semi lattice exception.
	 *
	 * @param msg the msg
	 */
	public NotInSemiLatticeException( String msg ) 
	{
        	super( msg );
	}
}
