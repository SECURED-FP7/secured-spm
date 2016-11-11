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
 * The Enum SetComparison.
 */
public enum SetComparison {
	
	/** The equivalent. */
	EQUIVALENT, 
 /** The subset. */
 SUBSET, 
 /** The superset. */
 SUPERSET, 
 /** The INTERSECTIN g_but_ no n_ empt y_ difference. */
 INTERSECTING_but_NON_EMPTY_DIFFERENCE, 
 /** The disjoint. */
 DISJOINT;
	
}
