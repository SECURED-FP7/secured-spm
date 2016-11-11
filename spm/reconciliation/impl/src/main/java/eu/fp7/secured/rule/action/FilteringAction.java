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
 * The Enum FilteringAction.
 */
public enum FilteringAction implements Action {
	
	/** The deny. */
	DENY, 
 /** The allow. */
 ALLOW, 
 /** The dummy. */
 DUMMY, 
 /** The inconsistent. */
 INCONSISTENT, 
 /** The hidden inconsistent. */
 HIDDEN_INCONSISTENT, 
 /** The nat. */
 NAT;

	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		if(this == DENY)
			return "DENY";
		else if (this == ALLOW)
			return "ALLOW";
		else if (this == DUMMY)
			return "DUMMY";
		else if (this == NAT)
			return "NAT";
		else if (this == HIDDEN_INCONSISTENT)
			return "HIDDEN_INCONSISTENT";
		else return "INCONSISTENT";
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return this;
	}
}
