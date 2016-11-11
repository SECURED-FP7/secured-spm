package eu.fp7.secured.policy.resolution.impl;

public enum SetEnum { 
	MRS, GRS, LRS1, LRS2, LRS3, LRS4, LRS5, LRS6, LRS7, LRS8, LRS9;
	
	//Trovare modo + furbo per gli LRSs
	
	public String toString(){
		if (this==MRS)
			return "MRS";
		if (this==GRS)
			return "GRS";
		
		return "LRS"+(this.ordinal()-1);
		
	}

}
