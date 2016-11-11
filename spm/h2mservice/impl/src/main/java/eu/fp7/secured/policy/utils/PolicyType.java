package eu.fp7.secured.policy.utils;

public enum  PolicyType {
	FILTERING, NAT, VPN;
	
	public String toString(){
		if(this == FILTERING)
			return "FILTERING";
		else if (this == NAT)
			return "NAT";
		else if (this == VPN)
			return "VPN";
		return "";
	}
	
}
