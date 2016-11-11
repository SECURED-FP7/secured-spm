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
package eu.fp7.secured.policy.resolution.impl;

/**
 * The Enum SetEnum.
 */
public enum SetEnum { 
	
	/** The mrs. */
	MRS, 
 /** The grs. */
 GRS, 
 /** The LR s1. */
 LRS1, 
 /** The LR s2. */
 LRS2, 
 /** The LR s3. */
 LRS3, 
 /** The LR s4. */
 LRS4, 
 /** The LR s5. */
 LRS5, 
 /** The LR s6. */
 LRS6, 
 /** The LR s7. */
 LRS7, 
 /** The LR s8. */
 LRS8, 
 /** The LR s9. */
 LRS9;
	
	//Trovare modo + furbo per gli LRSs
	
	/* (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		if (this==MRS)
			return "MRS";
		if (this==GRS)
			return "GRS";
		
		return "LRS"+(this.ordinal()-1);
		
	}

}
