package eu.fp7.secured.policy.anomaly;


import eu.fp7.secured.policy.anomaly.utils.ConflictType;

// TODO: Auto-generated Javadoc
/**
 * The Class PolicyConflictResult is a container class which contains a conflict type 
 * and the security level in two private member variables:
 * conflict
 * secLevel
 */
public class PolicyConflictResult {

	/** The private member variable conflict contains the conflict type */
	private ConflictType conflict;
	
	/** The private member variable secLevel contains the security level. */
	private int secLevel;
	
	/**
	 * Instantiates a new policy conflict result.
	 *
	 * @param conflict the conflict
	 * @param secLevel the sec level
	 */
	public PolicyConflictResult(ConflictType conflict, int secLevel){
		this.conflict = conflict;
		this.secLevel = secLevel;
	}

	/**
	 * Instantiates a new policy conflict result.
	 *
	 * @param conflict the conflict
	 */
	public PolicyConflictResult(ConflictType conflict){
		this.conflict = conflict;
		this.secLevel = -1;
	}
	

	/**
	 * Gets the conflict.
	 *
	 * @return the conflict
	 */
	public ConflictType getConflict() {
		return conflict;
	}
	
	/**
	 * Gets the sec level.
	 *
	 * @return the sec level
	 */
	public int getSecLevel(){
		return secLevel;
	}
}
