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
package eu.fp7.secured.policy.externaldata;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;


/**
 * The Class UniqueValueExternalDataManager.
 *
 * @param <GenericRule> the generic type
 * @param <S> the generic type
 */
@SuppressWarnings("hiding")
public class UniqueValueExternalDataManager<GenericRule, S> extends ExternalDataManager<GenericRule,S> {
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.externaldata.ExternalDataManager#setExternalData(java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException{
		if(super.data.containsKey(externalData))
			throw new DuplicateExternalDataException();
		
		this.data.put(rule, externalData);
	}

}
