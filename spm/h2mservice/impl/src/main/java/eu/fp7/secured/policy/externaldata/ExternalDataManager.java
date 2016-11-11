package eu.fp7.secured.policy.externaldata;

import java.util.HashMap;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;


@SuppressWarnings("hiding")
public class ExternalDataManager<GenericRule, S> {

	protected HashMap<GenericRule, S> data;

	public ExternalDataManager() {
		data = new HashMap<GenericRule, S>();
	}
	
	private ExternalDataManager(HashMap<GenericRule, S> data) {
		this.data = data;
	}

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
	
	public void printExternalData(GenericRule rule)
	{
		StringBuffer buffer = new StringBuffer();
		buffer.append(rule.toString());
		buffer.append(" -->"+data.get(rule).toString()+"\n");
		System.out.println(buffer);
	}
	
	/**
	 * 
	 * @param rule
	 * @param data
	 * @throws DuplicateExternalDataException 
	 */
	public void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException{
		this.data.put(rule, externalData);
	}
	
	public void clearExternalData(GenericRule rule){
		data.remove(rule);
	}
	
	public boolean isRuleManaged(GenericRule rule){
		return data.containsKey(rule);
	}
	
	public S getExternalData(GenericRule rule){
		return data.get(rule);
	}
	
	@SuppressWarnings("unchecked")
	public ExternalDataManager<GenericRule, S> cloneExternalDataManager(){
		return new ExternalDataManager<GenericRule, S>((HashMap<GenericRule, S>) data.clone());
	}
	
	public boolean isExternalDataAssociated(S externalData){
		return data.containsValue(externalData);
	}
	
	public void cloneExternalData(GenericRule from, GenericRule to) throws NoExternalDataException {
		if(!data.containsKey(from)){
			throw new NoExternalDataException();
		}
		data.put(to, data.get(from));
	}
	
	public void importFrom(ExternalDataResolutionStrategy<GenericRule, S> resolutionStrategy, GenericRule rule){
		S ed = resolutionStrategy.getExternalData(rule);
		data.put(rule, ed);
	}
	
	public void clear(){
		data.clear();
	}
}
