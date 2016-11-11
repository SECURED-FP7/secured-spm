package eu.fp7.secured.rule.action;

/**
 * 
 * This enum implements a filter action of a device like a router or a firewall.
 * Admitted values are ALLOW, DENY, DUMMY and INCONSISTENT that is used as default action for
 * the semilattice TOP element. 
 * 
 */
public enum FilteringAction implements Action {
	DENY, ALLOW, DUMMY, INCONSISTENT, HIDDEN_INCONSISTENT, NAT;

	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		if(this == DENY)
			return "DENY";
		else if (this == ALLOW)
			return "ALLOW";
		else if (this == DUMMY)
			return "DUMMY";
		else if (this == NAT)
			return "NAT";
		else if (this == HIDDEN_INCONSISTENT)
			return "HIDDEN_INCONSISTENT";
		else return "INCONSISTENT";
	}
	
	@Override
	public Action actionClone() {
		return this;
	}
}
