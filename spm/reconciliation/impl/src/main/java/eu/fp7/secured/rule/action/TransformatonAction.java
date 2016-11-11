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
 * The Class TransformatonAction.
 */
public abstract class TransformatonAction implements Action  {
	
	/** The transformation. */
	private ConditionClause transformation;
	
	/**
	 * Instantiates a new transformaton action.
	 *
	 * @param transformation the transformation
	 */
	public TransformatonAction(ConditionClause transformation){
		this.transformation=transformation;
	}
	
	/**
	 * Gets the transformation.
	 *
	 * @return the transformation
	 */
	public ConditionClause getTransformation(){
		return transformation;
	}

	
}
