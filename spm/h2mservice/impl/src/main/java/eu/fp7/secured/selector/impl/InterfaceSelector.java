package eu.fp7.secured.selector.impl;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;
import eu.fp7.secured.rule.selector.Selector;


public class InterfaceSelector extends ExactMatchSelectorImpl {
	
	public String [] interfaceName = {"LAN","WAN","eth0"};
	
	private int MAX_VALUE=2,MIN_VALUE=0;
	
	public InterfaceSelector(){
		ranges = new RealBitSet();
	}

	@Override
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
		
		for (i=0;i<interfaceName.length && !stop;i++) {
			if (value.equalsIgnoreCase(interfaceName[i]))
				stop = true;
		}
		if (stop) {
			addRange(--i);
			
		} else {
			int val = Integer.parseInt(value);
			
			if (val<=MAX_VALUE && val>=MIN_VALUE)
				addRange(val);
			else throw new IllegalArgumentException();
		}

	}
	
	public void addRange(int value) throws InvalidRangeException{
		if (value<MIN_VALUE || value>MAX_VALUE){
			System.out.println(value);
			throw new InvalidRangeException("Value: "+value);
		}
		
		ranges.set(value);
	}

	public int getMAX_VALUE() {
		return MAX_VALUE;
	}

	public int getMIN_VALUE() {
		return MIN_VALUE;
	}

	@Override
	public int getElementsNumber() {
		return MAX_VALUE+1;
	}

	@Override
	public Selector selectorClone() {
		InterfaceSelector is = new InterfaceSelector();
		is.ranges = (RealBitSet)ranges.clone(); 
		return is;
	}

	@Override
	public String toSimpleString() {
		if (this.isEmpty())
			return "";
		if (this.isFull())
			return "*";
		
		//int bitSet=0;
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
			str = str + interfaceName[i]+",";
		 }
		return str;
	}
	
	@Override
	public String toString(){
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";
		
		//int bitSet=0;
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
			str = str + "["+i+"-"+interfaceName[i]+"] ";
		 }
		return str;
	}



}
