package eu.fp7.secured.selector.impl;


import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.RealBitSet;


public class DirectionSelector extends ExactMatchSelectorImpl {
	
	public DirectionSelector(){
		this.ranges = new RealBitSet(MAX_VALUE+1);
	}

	public static String [] direction={"IN", "OUT"};
	
	private static int MAX_VALUE=1, MIN_VALUE=0;

	
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
		
		for (i=0;i<direction.length && !stop;i++) {
			if (value.equalsIgnoreCase(direction[i]))
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

	public DirectionSelector selectorClone() {
		DirectionSelector pid = new DirectionSelector();
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
				str = str + "["+direction[i]+"] ";
		 }
		return str;
	}

	public String toSimpleString() {
		String str="";
		
		for (int i = ranges.nextSetBit(0); i >= 0; i = ranges.nextSetBit(i+1)) {
				str = str + direction[i];
				if(ranges.nextSetBit(i+1) >= 0)
					str = str + ";";
		 }
		return str;
	}


	public static int getMAX_VALUE() {
		return MAX_VALUE;
	}

	public static int getMIN_VALUE() {
		return MIN_VALUE;
	}

	@Override
	public int getElementsNumber() {
		return MAX_VALUE+1;
	}

	@Override
	public void full() {
		ranges.set(0);
		ranges.set(1);
	}
}
