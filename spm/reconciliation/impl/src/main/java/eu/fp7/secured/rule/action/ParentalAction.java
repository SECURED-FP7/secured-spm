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

import eu.fp7.secured.mspl.DataProtectionAction;
import eu.fp7.secured.mspl.ParentalControlAction;
import eu.fp7.secured.mspl.ReencryptNetworkConfiguration;

/**
 * The Class DataProtAction.
 */
public class ParentalAction implements Action {
	
	/** The action. */
	private ParentalControlAction action;
	
	/**
	 * Instantiates a new data prot action.
	 *
	 * @param action the action
	 */
	public ParentalAction(ParentalControlAction action){
		this.action = action;
	}
	
	/**
	 * Gets the action.
	 *
	 * @return the action
	 */
	public ParentalControlAction getAction(){
		return action;
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	@Override
	public String toString(){
		return action.getEnableActionType().toString()+" "+action.getPics().getSafeNet();
	}

		
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return this;
	}

}
