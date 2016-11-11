package eu.fp7.secured.policy.utils;

import java.util.BitSet;

import eu.fp7.secured.rule.selector.RegExpSelector;

public class RegexBlock implements Block{
	
	RegExpSelector s;
	BitSet bs;
	
	public RegexBlock(RegExpSelector s){
		this.s=s;
		bs = new BitSet();
	}

	@Override
	public BitSet getBs() {
		return bs;
	}
	public void setBs(BitSet bs) {
		this.bs=bs;
	}
	public RegExpSelector getSelector(){
		return s;
	}

	@Override
	public String toString() {
		return s.toString();
	}
}
