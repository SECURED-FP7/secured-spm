package eu.fp7.secured.selector.impl;


import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;



public class UriSelector extends ExactMatchSelectorImpl {

	//smb and icp, not present in iana, added by developers
	public static String [] uri={"aaa","acap","cap","cid","crid","data","dav","dict","dns","fax",
		"file","ftp","go","gopher","h323","http","https","iax","icap","im","imap","info","ipp",
		"iris","iris.beep","iris.xpc","iris.xpcs","iris.lwz","ldap","mailto","mid","modem","msrp",
		"msrps","mtqp","mupdate","news","nfs","nntp","opaquelocktoken","pop","pres","rtsp","service",
		"shttp","sieve","sip","sips","snmp","soap.beep","soap.beeps","tag","tel","telnet","tftp",
		"thismessage","tip","tv","urn","vemmi","xmlrpc.beep","xmlrpc.beeps","xmpp","z39.50r","z39.50s",
		"smb","icp", "ssh"};
	
	private static int MIN_VALUE=0;
	private static int MAX_VALUE=uri.length-1;
	
	public static int getMIN_VALUE() {
		return MIN_VALUE;
	}

	public static int getMAX_VALUE() {
		return MAX_VALUE;
	}

	
	
	
	private static String selName="Uri";
	//TODO private ProtocolIDSelectorFactory factory;
	
	
	public UriSelector(){
		//factory = ProtocolIDSelectorFactory.getInstance();
		ranges = new RealBitSet(MAX_VALUE+1);
	}
	
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String)Value);
		else throw new InvalidRangeException();
		
	}
	
	public void addRange(int value) throws InvalidRangeException{
		if (value>=MIN_VALUE && value<=MAX_VALUE)
			ranges.set(value);
		else throw new InvalidRangeException();
	}
	
	public void addRange(String Value) throws InvalidRangeException{
		boolean stop = false;
		int i=0;
		for (i=0;i<uri.length && !stop;i++) {
			if (Value.equalsIgnoreCase(uri[i]))
				stop = true;
		}
		if (stop) {
			ranges.set(--i);;
			
		} else throw new IllegalArgumentException("Uri: "+Value);
	}



	@Override
	public UriSelector selectorClone() {
		UriSelector uri = new UriSelector();
		uri.ranges = (RealBitSet)ranges.clone(); 
		return uri;
	}

	@Override
	public String toSimpleString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "any";

		StringBuffer sb = new StringBuffer();
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
				sb.append(uri[i]);
				sb.append(";");
			}
		 
		return sb.toString();
	}
	

	
	public String toString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "any";

		StringBuffer sb = new StringBuffer();
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
				sb.append(uri[i]);
				sb.append(", ");
			}
		 
		return sb.toString();
	}

	@Override
	public int getElementsNumber() {
		return uri.length;
	}

}
