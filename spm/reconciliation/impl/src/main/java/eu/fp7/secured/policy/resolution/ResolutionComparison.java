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

/**
 * The Enum ResolutionComparison.
 */
public enum ResolutionComparison {
	
	/** The universally greater. */
	UNIVERSALLY_GREATER, 
 /** The universally less. */
 UNIVERSALLY_LESS, 
 /** The non universally comparable. */
 NON_UNIVERSALLY_COMPARABLE, 
 /** The equivalent. */
 EQUIVALENT, 
 /** The different set. */
 DIFFERENT_SET;
}
