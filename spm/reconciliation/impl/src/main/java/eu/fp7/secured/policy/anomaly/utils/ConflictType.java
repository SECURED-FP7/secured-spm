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
package eu.fp7.secured.policy.anomaly.utils;

/**
 * The Enum ConflictType.
 */
public enum ConflictType {
	
	/** The non intersecting. */
	NON_INTERSECTING, 
	
	/** The conflicting. */
	CONFLICTING, 
	
	/** The hidden. */
	HIDDEN, 
	
	/** The shadowed. */
	SHADOWED, 
	
	/** The redundant. */
	REDUNDANT, 
	
	/** The greater. */
	GREATER, 
	
	/** The less. */
	LESS,
	
	/** The n_ hidden. */
	n_HIDDEN, 
	
	/** The n_ shadowed. */
	n_SHADOWED, 
	
	/** The n_ redundant. */
	n_REDUNDANT, 
	
	/** The equivalent. */
	EQUIVALENT,
	
	/** The inconsistent. */
	INCONSISTENT,
	
	/** The INTERSECTIN g_but_ no t_ conflicting. */
	INTERSECTING_but_NOT_CONFLICTING,
	
	/** The GREATE r_but_ no t_ conflicting. */
	GREATER_but_NOT_CONFLICTING,	
	
	/** The LES s_but_ no t_ conflicting. */
	LESS_but_NOT_CONFLICTING,
	
	/** The hides. */
	HIDES,
	
	/** The makes redundant. */
	MAKES_REDUNDANT,
	
	/** The shadows. */
	SHADOWS,
	
	/** The RESOLUTIO n_ erro r_state_impossible. */
	RESOLUTION_ERROR_state_impossible,
	
	/** The identical. */
	IDENTICAL,
	
	/** The spurious. */
	SPURIOUS,
	
	/** The correlated. */
	CORRELATED, 
	
	/** The non conflicting. */
	NON_CONFLICTING,
	
	/** The ipsec overlap. */
	IPSEC_OVERLAP,
	
	/** The ipsec inconsistent. */
	IPSEC_INCONSISTENT,
	
	/** The seclevel conflict. */
	SECLEVEL_CONFLICT,
	
	/** The inter tech conflict. */
	INTER_TECH_CONFLICT;
}
