package eu.fp7.secured.policy.externaldata;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;


@SuppressWarnings("hiding")
public class UniqueValueExternalDataManager<GenericRule, S> extends ExternalDataManager<GenericRule,S> {
	
	@Override
	public void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException{
		if(super.data.containsKey(externalData))
			throw new DuplicateExternalDataException();
		
		this.data.put(rule, externalData);
	}

}
