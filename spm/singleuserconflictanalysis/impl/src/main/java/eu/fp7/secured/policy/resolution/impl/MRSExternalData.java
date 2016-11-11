package eu.fp7.secured.policy.resolution.impl;

public class MRSExternalData implements Cloneable{
	
	protected int internalPriority;
	
	protected SetEnum set;
	
	public MRSExternalData(int priority, SetEnum set){
		internalPriority = priority;
		this.set = set;
	}

	public int getInternalPriority() {
		return internalPriority;
	}

	public SetEnum getSet() {
		return set;
	}
	
	public MRSExternalData clone(){
		
		return new MRSExternalData(internalPriority, set);
	
	}
	
	public String toString(){
		return this.set+" prio: "+internalPriority;
	}
	
	

	
}
