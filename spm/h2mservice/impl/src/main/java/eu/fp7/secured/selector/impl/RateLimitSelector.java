package eu.fp7.secured.selector.impl;

import java.util.BitSet;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.Selector;

public class RateLimitSelector implements Selector{
	
	private int rateLimit;

	@Override
	public void empty() {
		rateLimit = 0;
	}

	@Override
	public Selector selectorClone() {
		RateLimitSelector rateLimitSelector = new RateLimitSelector();
		try {
			rateLimitSelector.addRange(rateLimit);
		} catch (InvalidRangeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return rateLimitSelector;
	}

	@Override
	public boolean isEmpty() {
		if(rateLimit == 0)
			return true;
		return false;
	}

	@Override
	public boolean isFull() {
		if(rateLimit == -1)
			return true;
		return false;
	}

	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit < rateLimit)
			rateLimit = ((RateLimitSelector)s).rateLimit;
	}

	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit > rateLimit)
			rateLimit = ((RateLimitSelector)s).rateLimit;
	}

	

	@Override
	public void complement() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit == rateLimit)
			return true;
		return false;
	}

	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit < rateLimit)
			return true;
		return false;
	}

	@Override
	public boolean isSubsetOrEquivalent(Selector s)
			throws IllegalArgumentException {
		if (((RateLimitSelector)s).rateLimit <= rateLimit)
			return true;
		return false;
	}

	@Override
	public String toSimpleString() {
		return rateLimit+"/s";
	}
	
	@Override
	public String toString() {
		return "["+rateLimit+"/s]";
	}

	@Override
	public int getFirstAssignedValue() {
		// TODO Auto-generated method stub
		return rateLimit;
	}

	@Override
	public long length() {
		// TODO Auto-generated method stub
		return 1;
	}


	@Override
	public boolean isPoint() {
		return true;
	}

	@Override
	public void full() {
		rateLimit = -1;
	}

	public void addRange(Object Value) throws InvalidRangeException {
		rateLimit = (Integer)Value;
	}



}
