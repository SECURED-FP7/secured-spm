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
package eu.fp7.secured.reconciliation;

import java.util.LinkedList;

/**
 * The Class ReconciliationResult.
 */
public class ReconciliationResult {
	
	/** The report. */
	public String report;
	
	/** The app_graph. */
	public String app_graph;
	
	/** The MSP ls. */
	public LinkedList<String> MSPLs;
}
