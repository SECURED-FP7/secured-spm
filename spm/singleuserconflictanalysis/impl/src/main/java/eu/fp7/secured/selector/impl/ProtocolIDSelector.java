package eu.fp7.secured.selector.impl;


import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;


public class ProtocolIDSelector extends ExactMatchSelectorImpl {
	
	public ProtocolIDSelector(){
		this.ranges = new RealBitSet(MAX_VALUE+1);
	}

	public static String [] protocol={"HOPOPT", "ICMP", "IGMP", "GGP", "IP", "ST", "TCP", "CBT", "EGP", "IGP",
		"BBN-RCC-MON", "NVP-II", "PUP",	"ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP","PRM", "XNS-IDP",
		"TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP",
		"3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP",
		"RSVP", "GRE", "MHRP", "BNA", "ESP", "AH", "I-NLSP", "SWIPE", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP",
		"IPv6-NoNxt", "IPv6-Opts", "any protocol", "CFTP", "any lan", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", 
		"any distribuited fs", "SAT-MON", "VISA", "IPCV", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND",
		"WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP", "NSFNET-IGP", "DGP", "TCF", "EIGRP",
		"OSPFIGP", "Sprite-RPC", "LARP", "MTP", "AX.25", "IPIP", "MICP", "SCC-SP", "ETHERIP", "ENCAP",
		"any private encryption scheme", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp",
		"SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "any 0-hop protocol", "L2TP", "DDX", "IATP", "STP", "SRP",
		"UTI", "SMP", "SM", "PTP", "ISIS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE",
		"SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP"};
	
	
	private static int MAX_VALUE=63, MIN_VALUE=0;



	
//	public ProtocolIDSelector(){
//		
//	}
	
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String)Value);
		else if (Value instanceof java.lang.Integer)
			addRange((Integer)Value);
		else throw new InvalidRangeException();
	}
	
	public void addRange(String value) throws InvalidRangeException{
		boolean stop = false;
		int i=0;
		
		if (value.equalsIgnoreCase("any")){
			for(i=0;i<=MAX_VALUE;i++)
				ranges.set(i);
			return;
		}
		
		for (i=0;i<protocol.length && !stop;i++) {
			if (value.equalsIgnoreCase(protocol[i]))
				stop = true;
		}
		if (stop) {
			addRange(--i);
			
		} else {
			int val = Integer.parseInt(value);
			
			if (val<=MAX_VALUE && val>=0)
				addRange(val);
			else throw new IllegalArgumentException();
		}

	}
	
	public void addRange(Integer value){
		System.err.println("ProtocolIDSelector.addRange(Integer value) da implementare");
	}
	
	public void addRange(int value) throws InvalidRangeException{
		if (value<0 || value>MAX_VALUE){
			System.out.println(value);
			throw new InvalidRangeException("Value: "+value);
		}
		
		ranges.set(value);
	}

	public ProtocolIDSelector selectorClone() {
		ProtocolIDSelector pid = new ProtocolIDSelector();
		pid.ranges = (RealBitSet)ranges.clone(); 
		return pid;
	}
	
	public String toString(){
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";
		
		//int bitSet=0;
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
			if (i<138)
				str = str + "["+i+"-"+protocol[i]+"] ";
			else if (i<253)
				str = str + "["+i+"-Unassigned] ";
			else if (i<255)
				str = str + "["+i+"-Experimentation/testing] ";
			else str = str + "["+i+"-Reserved] ";
		 }
		return str;
	}

	public String toSimpleString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "any";

		StringBuffer sb = new StringBuffer();
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
			if (i<138){
				if (sb.length()>0)
					sb.append(";");
				sb.append(protocol[i]);
			} else if (i<253){
				if (sb.length()>0)
					sb.append(";");
				sb.append(i);
			} else if (i<255) {
				if (sb.length()>0)
					sb.append(";");
				sb.append(i);
			} else {
				if (sb.length()>0)
					sb.append(";");
				sb.append(i);
			}
		 }
		return sb.toString();
	}
	

	@Override
	public int getElementsNumber() {
		return MAX_VALUE+1;
	}
	
	public static int getMAX_VALUE() {
		return MAX_VALUE;
	}

	public static int getMIN_VALUE() {
		return MIN_VALUE;
	}

}
