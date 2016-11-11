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
package eu.fp7.secured.rule.action;

/**
 * The Enum IPSecActionType.
 */
public enum IPSecActionType implements Action{
	
	/** The ah. */
	AH, 
 /** The invert ah. */
 INVERT_AH, 
 /** The esp. */
 ESP, 
 /** The invert esp. */
 INVERT_ESP;
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return this;
	}
}
