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
 * The Class OperationNotPossibleException.
 */
public class OperationNotPossibleException extends Exception{

	/** The Constant serialVersionUID. */
	static final long serialVersionUID = 19L;
	
	/**
	 * Instantiates a new operation not possible exception.
	 */
	public OperationNotPossibleException(){}

	/**
	 * Instantiates a new operation not possible exception.
	 *
	 * @param msg the msg
	 */
	public OperationNotPossibleException(String msg)
	{
		super(msg);
	}

}