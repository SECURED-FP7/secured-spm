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
package eu.fp7.secured.rule.selector;


/**
 * The Interface RegExpSelector.
 */
public interface RegExpSelector extends Selector{

	//public void setRegExp(RegExp regexp);
	 
 	/**
	 * Sets the reg exp.
	 *
	 * @param regexp the new reg exp
	 */
	public void setRegExp(String regexp);
	
}
