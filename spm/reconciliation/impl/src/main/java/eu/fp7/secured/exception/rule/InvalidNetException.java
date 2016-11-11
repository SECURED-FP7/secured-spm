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
package eu.fp7.secured.exception.rule;

/**
 * The Class InvalidNetException.
 */
public class InvalidNetException extends Exception {

	/** The Constant serialVersionUID. */
	static final long serialVersionUID = 15L;
	
	/**
	 * Instantiates a new invalid net exception.
	 */
	public InvalidNetException(){}

	/**
	 * Instantiates a new invalid net exception.
	 *
	 * @param msg the msg
	 */
	public InvalidNetException(String msg)
	{
		super(msg);
	}
}

