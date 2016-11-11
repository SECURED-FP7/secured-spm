package eu.fp7.secured.policy.utils;

import java.util.BitSet;
import java.util.HashMap;
import java.util.List;

import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.rule.selector.Selector;

public interface BlockList {

	public boolean insert(Selector s, int index) throws UnsupportedSelectorException;
	public List<Block> getBlocks();
	public List<Selector> getBlocksAsSelectors();
	public HashMap<Selector, BitSet> getBlocksAndBitSets();
	public boolean atLeastOneLabel();
	public BitSet getBitSet(int index);
	
}
