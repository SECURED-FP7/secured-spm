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
import eu.fp7.secured.mspl.ReduceBandwidthActionType;

/**
 * The Enum FilteringAction.
 */
public class ReduceBandwidthAction implements Action {
	
	ReduceBandwidthActionType actionType;
	
	public ReduceBandwidthAction(ReduceBandwidthActionType actionType){
		this.actionType = actionType;
	}
	
	public ReduceBandwidthActionType getActionType(){
		return actionType;
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		return "DOWN="+actionType.getDownlinkBandwidthValue()+" UP="+actionType.getUplinkBandwidthValue();
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		ReduceBandwidthActionType at = new ReduceBandwidthActionType();
		at.setDownlinkBandwidthValue(actionType.getDownlinkBandwidthValue());
		at.setUplinkBandwidthValue(actionType.getUplinkBandwidthValue());
		return new ReduceBandwidthAction(at);
	}
}
