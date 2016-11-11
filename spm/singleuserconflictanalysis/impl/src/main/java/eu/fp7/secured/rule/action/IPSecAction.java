package eu.fp7.secured.rule.action;

import eu.fp7.secured.rule.impl.ConditionClause;

public class IPSecAction extends TransformatonAction{
	
	private String key;
	private String hash_key;
	private IPSecActionType type;
	
	public IPSecAction(String key, String hash_key, IPSecActionType type, ConditionClause tunnel){
		super(tunnel);
		this.key=key;
		this.hash_key=hash_key;
		this.type=type;
	}
	
	public String getKey(){
		return key;
	}
	
	public String getHashKey(){
		return hash_key;
	}
	
	public IPSecActionType getType(){
		return type;
	}
	
	public boolean isEqual(IPSecAction ipSecAction){
		if(this.key.equals(ipSecAction.getKey()) && 
		   this.hash_key.equals(ipSecAction.getHashKey()) &&
		   this.type.equals(ipSecAction.getType()))
			return true;
		return false;
	}
	
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

	@Override
	public Action actionClone() {
		return new IPSecAction(key, hash_key, type, getTransformation().conditionClauseClone());
	}
}
