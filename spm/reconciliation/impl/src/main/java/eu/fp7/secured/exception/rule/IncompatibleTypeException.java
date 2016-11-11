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
 * The Class IncompatibleTypeException.
 */
public class IncompatibleTypeException extends Exception{

	/** The Constant serialVersionUID. */
	static final long serialVersionUID = 13L;
	
	/**
	 * Instantiates a new incompatible type exception.
	 */
	public IncompatibleTypeException(){}

	/**
	 * Instantiates a new incompatible type exception.
	 *
	 * @param msg the msg
	 */
	public IncompatibleTypeException(String msg)
	{
		super(msg);
	}

}