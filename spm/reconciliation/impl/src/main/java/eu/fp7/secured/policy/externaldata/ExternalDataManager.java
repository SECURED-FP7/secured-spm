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

import java.util.HashMap;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;


/**
 * The Class ExternalDataManager.
 *
 * @param <GenericRule> the generic type
 * @param <S> the generic type
 */
@SuppressWarnings("hiding")
public class ExternalDataManager<GenericRule, S> {

	/** The data. */
	protected HashMap<GenericRule, S> data;

	/**
	 * Instantiates a new external data manager.
	 */
	public ExternalDataManager() {
		data = new HashMap<GenericRule, S>();
	}
	
	/**
	 * Instantiates a new external data manager.
	 *
	 * @param data the data
	 */
	private ExternalDataManager(HashMap<GenericRule, S> data) {
		this.data = data;
	}

	/**
	 * Prints the external data.
	 */
	public void printExternalData()
	{
		StringBuffer buffer = new StringBuffer();
		for(GenericRule rule: data.keySet())
		{
			buffer.append(rule.toString());
			buffer.append(" -->"+data.get(rule).toString()+"\n");
		}
		System.out.println(buffer);
	}
	
	/**
	 * Prints the external data.
	 *
	 * @param rule the rule
	 */
	public void printExternalData(GenericRule rule)
	{
		StringBuffer buffer = new StringBuffer();
		buffer.append(rule.toString());
		buffer.append(" -->"+data.get(rule).toString()+"\n");
		System.out.println(buffer);
	}
	
	/**
	 * Sets the external data.
	 *
	 * @param rule the rule
	 * @param externalData the external data
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 */
	public void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException{
		this.data.put(rule, externalData);
	}
	
	/**
	 * Clear external data.
	 *
	 * @param rule the rule
	 */
	public void clearExternalData(GenericRule rule){
		data.remove(rule);
	}
	
	/**
	 * Checks if is rule managed.
	 *
	 * @param rule the rule
	 * @return true, if is rule managed
	 */
	public boolean isRuleManaged(GenericRule rule){
		return data.containsKey(rule);
	}
	
	/**
	 * Gets the external data.
	 *
	 * @param rule the rule
	 * @return the external data
	 */
	public S getExternalData(GenericRule rule){
		return data.get(rule);
	}
	
	/**
	 * Clones the external data manager.
	 *
	 * @return the external data manager
	 */
	@SuppressWarnings("unchecked")
	public ExternalDataManager<GenericRule, S> cloneExternalDataManager(){
		return new ExternalDataManager<GenericRule, S>((HashMap<GenericRule, S>) data.clone());
	}
	
	/**
	 * Checks if is external data associated.
	 *
	 * @param externalData the external data
	 * @return true, if is external data associated
	 */
	public boolean isExternalDataAssociated(S externalData){
		return data.containsValue(externalData);
	}
	
	/**
	 * Clones the external data.
	 *
	 * @param from the from
	 * @param to the to
	 * @throws NoExternalDataException the no external data exception
	 */
	public void cloneExternalData(GenericRule from, GenericRule to) throws NoExternalDataException {
		if(!data.containsKey(from)){
			throw new NoExternalDataException();
		}
		data.put(to, data.get(from));
	}
	
	/**
	 * Import from.
	 *
	 * @param resolutionStrategy the resolution strategy
	 * @param rule the rule
	 */
	public void importFrom(ExternalDataResolutionStrategy<GenericRule, S> resolutionStrategy, GenericRule rule){
		S ed = resolutionStrategy.getExternalData(rule);
		data.put(rule, ed);
	}
	
	/**
	 * Clear.
	 */
	public void clear(){
		data.clear();
	}
}
