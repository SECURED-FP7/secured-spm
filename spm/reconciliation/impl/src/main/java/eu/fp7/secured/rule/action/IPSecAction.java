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
 * The Class IPSecAction.
 */
public class IPSecAction extends TransformatonAction{
	
	/** The key. */
	private String key;
	
	/** The hash_key. */
	private String hash_key;
	
	/** The type. */
	private IPSecActionType type;
	
	/**
	 * Instantiates a new IP sec action.
	 *
	 * @param key the key
	 * @param hash_key the hash_key
	 * @param type the type
	 * @param tunnel the tunnel
	 */
	public IPSecAction(String key, String hash_key, IPSecActionType type, ConditionClause tunnel){
		super(tunnel);
		this.key=key;
		this.hash_key=hash_key;
		this.type=type;
	}
	
	/**
	 * Gets the key.
	 *
	 * @return the key
	 */
	public String getKey(){
		return key;
	}
	
	/**
	 * Gets the hash key.
	 *
	 * @return the hash key
	 */
	public String getHashKey(){
		return hash_key;
	}
	
	/**
	 * Gets the type.
	 *
	 * @return the type
	 */
	public IPSecActionType getType(){
		return type;
	}
	
	/**
	 * Checks if is equal.
	 *
	 * @param ipSecAction the ip sec action
	 * @return true, if is equal
	 */
	public boolean isEqual(IPSecAction ipSecAction){
		if(this.key.equals(ipSecAction.getKey()) && 
		   this.hash_key.equals(ipSecAction.getHashKey()) &&
		   this.type.equals(ipSecAction.getType()))
			return true;
		return false;
	}
	
	/**
	 * Checks if is invert equal.
	 *
	 * @param ipSecAction the ip sec action
	 * @return true, if is invert equal
	 */
	public boolean isInvertEqual(IPSecAction ipSecAction) {
		if((this.type==IPSecActionType.AH && ipSecAction.getType()==IPSecActionType.INVERT_AH) ||
			(this.type==IPSecActionType.INVERT_AH && ipSecAction.getType()==IPSecActionType.AH))
			if(this.hash_key.equals(ipSecAction.getHashKey()))
					return true;
		if((this.type==IPSecActionType.ESP && ipSecAction.getType()==IPSecActionType.INVERT_ESP) ||
			(this.type==IPSecActionType.INVERT_ESP && ipSecAction.getType()==IPSecActionType.ESP))
			if(this.key.equals(ipSecAction.getKey()) && this.hash_key.equals(ipSecAction.getHashKey()))
					return true;
		return false;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString(){
		if(type==IPSecActionType.AH)
			return "AH("+hash_key+")";
		if(type==IPSecActionType.INVERT_AH)
			return "INVERT_AH("+hash_key+")";
		if(type==IPSecActionType.ESP)
			return "ESP("+hash_key+","+key+")";
		if(type==IPSecActionType.INVERT_ESP)
			return "INVERT_ESP("+hash_key+","+key+")";
		return "IPSEC("+hash_key+","+key+")";
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return new IPSecAction(key, hash_key, type, getTransformation().conditionClauseClone());
	}
}
