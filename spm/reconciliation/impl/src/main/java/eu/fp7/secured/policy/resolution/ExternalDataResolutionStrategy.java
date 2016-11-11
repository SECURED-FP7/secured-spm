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
package eu.fp7.secured.policy.resolution;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;

/**
 * The Class ExternalDataResolutionStrategy.
 *
 * @param <GenericRule> the generic type
 * @param <S> the generic type
 */
public abstract class ExternalDataResolutionStrategy<GenericRule, S> extends GenericConflictResolutionStrategy
{
	
	/**
	 * Compose external data.
	 *
	 * @param r1 the r1
	 * @param r2 the r2
	 * @return the s
	 * @throws NoExternalDataException the no external data exception
	 */
	public abstract S composeExternalData(GenericRule r1, GenericRule r2) throws NoExternalDataException;
	
	/**
	 * Sets the external data.
	 *
	 * @param rule the rule
	 * @param externalData the external data
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 */
	public abstract void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException;
	
	/**
	 * Compose external data.
	 *
	 * @param rules the rules
	 * @return the s
	 * @throws NoExternalDataException the no external data exception
	 */
	public abstract S composeExternalData(GenericRule[] rules) throws NoExternalDataException;
	
	/**
	 * Gets the external data.
	 *
	 * @param rule the rule
	 * @return the external data
	 */
	public abstract S getExternalData(GenericRule rule);
	
	/**
	 * Clear external data.
	 *
	 * @param rule the rule
	 */
	public abstract void clearExternalData(GenericRule rule);
	
	/**
	 * Checks if is rule managed.
	 *
	 * @param rule the rule
	 * @return true, if is rule managed
	 */
	public abstract boolean isRuleManaged(GenericRule rule);
}