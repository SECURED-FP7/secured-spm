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

import java.util.LinkedList;

/**
 * The Class IPSecActionSet.
 */
public class IPSecActionSet implements Action{

	/** The ip sec action list. */
	private LinkedList<IPSecAction> ipSecActionList;
	
	/**
	 * Instantiates a new IP sec action set.
	 *
	 * @param ipSecActionList the ip sec action list
	 */
	public IPSecActionSet(LinkedList<IPSecAction> ipSecActionList){
		this.ipSecActionList = ipSecActionList;
	}
	
	/**
	 * Gets the sec action list.
	 *
	 * @return the sec action list
	 */
	public LinkedList<IPSecAction> getSecActionList(){
		return ipSecActionList;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		String ret="";
		for(IPSecAction action:ipSecActionList){
			ret+="\n"+action.toString();
		}
		return ret;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		LinkedList<IPSecAction> new_ipSecActionList = new LinkedList<IPSecAction>();
		for(IPSecAction a:ipSecActionList){
			new_ipSecActionList.add((IPSecAction)a.actionClone());
		}
		return new IPSecActionSet(new_ipSecActionList);
	}
}
