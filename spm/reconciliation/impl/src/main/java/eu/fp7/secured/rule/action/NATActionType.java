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
 * The Enum NATActionType.
 */
public enum NATActionType implements Action{
	
	/** The prenat. */
	PRENAT, 
 /** The postnat. */
 POSTNAT;
	
	/* (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	@Override
	public String toString(){
		if(this == PRENAT)
			return "PRENAT";
		else if (this == POSTNAT)
			return "POSTNAT";
		return "";
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return this;
	}
}
