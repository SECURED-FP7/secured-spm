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
 * The Class UnsupportedSelectorException.
 */
public class UnsupportedSelectorException extends Exception{

	/** The Constant serialVersionUID. */
	static final long serialVersionUID = 12L;
	
	/**
	 * Instantiates a new unsupported selector exception.
	 */
	public UnsupportedSelectorException(){}

	/**
	 * Instantiates a new unsupported selector exception.
	 *
	 * @param msg the msg
	 */
	public UnsupportedSelectorException(String msg)
	{
		super(msg);
	}

}
