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

import eu.fp7.secured.rule.impl.ConditionClause;

/**
 * The Class NATAction.
 */
public class NATAction extends TransformatonAction{
	
	/** The NAT action. */
	private NATActionType NATAction;

	/**
	 * Instantiates a new NAT action.
	 *
	 * @param NATAction the NAT action
	 * @param transformation the transformation
	 */
	public NATAction(NATActionType NATAction, ConditionClause transformation) {
		super(transformation);
		this.NATAction = NATAction;
	}

	/**
	 * Gets the NAT action.
	 *
	 * @return the NAT action
	 */
	public NATActionType getNATAction() {
		return NATAction;
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return new NATAction(NATAction, getTransformation().conditionClauseClone());
	}
}
