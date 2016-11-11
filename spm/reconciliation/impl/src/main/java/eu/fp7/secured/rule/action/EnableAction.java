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

import eu.fp7.secured.mspl.EnableActionType;

/**
 * The Enum FilteringAction.
 */
public class EnableAction implements Action {
	
	EnableActionType actionType;
	
	public EnableAction(EnableActionType actionType){
		this.actionType = actionType;
	}
	
	public EnableActionType getActionType(){
		return actionType;
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		return actionType.getObjectToEnable()+" "+actionType.isEnable();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		EnableActionType at = new EnableActionType();
		at.setEnable(actionType.isEnable());
		at.setObjectToEnable(actionType.getObjectToEnable());
		return new EnableAction(at);
	}
}
