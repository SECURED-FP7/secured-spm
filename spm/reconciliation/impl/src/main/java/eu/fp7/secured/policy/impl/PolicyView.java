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

package eu.fp7.secured.policy.impl;

import java.util.LinkedList;

import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;

/**
 * The Class PolicyView.
 */
public class PolicyView extends PolicyImpl {

	/** The condition clause. */
	private ConditionClause	conditionClause;

	/**
	 * Instantiates a new policy view.
	 *
	 * @param resolutionStrategy the resolution strategy
	 * @param defaultAction the default action
	 * @param conditionClause the condition clause
	 * @param capability the capability
	 * @param name the name
	 * @param creator the creator
	 * @throws NoExternalDataException the no external data exception
	 */
	public PolicyView(GenericConflictResolutionStrategy resolutionStrategy, Action defaultAction, ConditionClause conditionClause, LinkedList<Capability> capability, String name, String creator) throws NoExternalDataException {

		super(resolutionStrategy, defaultAction, capability, name, creator);
		this.conditionClause = conditionClause;
	}

	/**
	 * Gets the condition clause.
	 *
	 * @return the condition clause
	 */
	public ConditionClause getConditionClause() {
		return this.conditionClause;
	}

}
