package eu.fp7.secured.policy.utils;

import java.util.BitSet;

public class BitSetManager {
	
	BitSet mask;
	int startingBit;
	int next_index;
	
	public BitSetManager()
	{
		next_index=1;
		startingBit = 1;
		mask = new IndexingBitSet();
	}
	
	public BitSetManager(int startingBit)
	{
		next_index=startingBit;
		mask = new IndexingBitSet();
	}

	
	public void clear(){
		next_index = 1;
		mask.clear();
	}
	
	public IndexingBitSet getIndex()
	{
		IndexingBitSet bs = new IndexingBitSet();
		bs.set(next_index);
		mask.set(next_index);
		next_index = mask.nextClearBit(next_index);
		return bs;
	}
	
	public void releaseIndex(IndexingBitSet bs)
	{
		int pos = bs.nextSetBit(startingBit -1);
		if(pos<next_index)
		{
			next_index = pos;
		}
		mask.clear(pos);
	}
	
	public int getMaxAssignedBit(){
		return mask.length()-1;
	}
	
	public int assignedBits(){
		return mask.cardinality();
	}

}
