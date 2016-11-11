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
import eu.fp7.secured.mspl.ReencryptNetworkConfiguration;

/**
 * The Class DataProtAction.
 */
public class AnonimityAction implements Action {
	
	/** The action. */
	private eu.fp7.secured.mspl.AnonimityAction action;
	
	/**
	 * Instantiates a new data prot action.
	 *
	 * @param action the action
	 */
	public AnonimityAction(eu.fp7.secured.mspl.AnonimityAction action){
		this.action = action;
	}
	
	/**
	 * Gets the action.
	 *
	 * @return the action
	 */
	public eu.fp7.secured.mspl.AnonimityAction getAction(){
		return action;
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	@Override
	public String toString(){
		return action.getEnableActionType().getObjectToEnable() + " " + action.getCountry().get(0);
	}

		
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return this;
	}

}
