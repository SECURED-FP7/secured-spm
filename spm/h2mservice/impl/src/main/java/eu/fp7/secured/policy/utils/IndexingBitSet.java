package eu.fp7.secured.policy.utils;

import java.util.BitSet;
import java.util.List;


@SuppressWarnings("rawtypes")
public class IndexingBitSet extends BitSet implements Comparable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 15L;
	static final int shift = 65536;

/*	public List generatePermutations(int n)
	{

		List<IndexingBitSet> res = null;
		
		
		if(n>this.cardinality())
			return res;
		else
		{
			res = new LinkedList<IndexingBitSet>();
			if(n == this.cardinality())
			{
				res.add(this);
			}
			else
			{
				IndexingBitSet bs = (IndexingBitSet)this.clone();
				remove_a_bit(bs, 0, n, /*this.cadinality(),*//* res);
			}
		}	
			
		return res;
	}

	public List generatePermutations(int n, BitSet fixed)
	{		
		List<IndexingBitSet> res = null;
		int left = this.cardinality() - n;
	
		if(left>this.cardinality())
			return res;
		else
		{
			res = new LinkedList<IndexingBitSet>();
			if(left == this.cardinality())
			{
				res.add(this);
			}
			else
			{
				IndexingBitSet bs = (IndexingBitSet)this.clone();
				remove_a_bit(bs, 0, left, /*this.cadinality(),*/ /*res, fixed);
			}
		}	
		
		return res;
		
	}
	*/
	public void remove_a_bit(IndexingBitSet bs, int pos, int left,/* int remaining,*/ List<IndexingBitSet> list, BitSet fixed)
	{
		//if(left == 0 /*|| remaining == 0*/)
		//{
		//	list.add(bs);
		//	return;
		//}*/
		
		bs.clear(pos);
		if(pos!=0)
			left--;
		//remaining--;
		/*if(pos == this.length()-1)
		{
			list.add(bs);
			return;
		}*/
		if(left == 0)
		{
			list.add(bs);
			return;

		}
		
		for(int i = bs.nextSetBit(pos); i >= 0; i = bs.nextSetBit(i+1))
		{
			if(fixed.get(i) == true)
			{
				continue;
			}
			IndexingBitSet bs1 = (IndexingBitSet)bs.clone();
			remove_a_bit(bs1,i,left,/*remaining,*/list,fixed);
		}
		
	}
	
	public void remove_a_bit(IndexingBitSet bs, int pos, int left,/* int remaining,*/ List<IndexingBitSet> list)
	{
		
		bs.clear(pos);
		if(pos!=0)
			left--;
		if(left == 0)
		{
			list.add(bs);
			return;

		}
		
		for(int i = bs.nextSetBit(pos); i >= 0; i = bs.nextSetBit(i+1))
		{
			IndexingBitSet bs1 = (IndexingBitSet)bs.clone();
			remove_a_bit(bs1,i,left,/*remaining,*/list);
		}
		
	}



	public int compareTo(Object o) {
		IndexingBitSet ibs = (IndexingBitSet) o;
		
		int cThis, cOther;
		cThis = this.cardinality();
		cOther = ibs.cardinality();
		
		if (cThis < cOther)
			return -1;
		
		if (cThis > cOther)
			return 1;
		
		if (cThis==cOther){
			cThis=this.nextSetBit(0);
			cOther=ibs.nextSetBit(0);
		
			if (cThis<cOther)
				return -1;
			if (cThis>cOther)
				return 1;
			
			for (int i=0;i<this.cardinality();i++){
				cThis=this.nextSetBit(cThis+1);
				cOther=ibs.nextSetBit(cOther+1);
				
				if (cThis<cOther)
					return -1;
				if (cThis>cOther)
					return 1;
			}
			/*do{
				if (cThis<cOther)
					return -1;
				if (cThis>cOther)
					return 1;
				
				if (this.cardinality()==cThis)
					break;
				
				//System.out.println("qui "+i);
				cThis=this.nextSetBit(cThis+1);
				cOther=ibs.nextSetBit(cOther+1);
				i++;
			} while(true);*/
		}
		return 0;
		
	}
	
	
	public boolean hasTheSameLabelsAs(IndexingBitSet ibs)
	{
		
		for(int i = this.nextSetBit(0); i >= 0; i = this.nextSetBit(i+1))
		{
			if(!ibs.get(i) == true)
			{
				return false;
			}
		}
		return this.cardinality()==ibs.cardinality();
	}
	
	//all the bit set to true in rule are also set to true in this
	public boolean hasAtLeastTheSameBitsAs(IndexingBitSet ibs)
	{
		for(int i = ibs.nextSetBit(0); i >= 0; i = ibs.nextSetBit(i+1))
		{
			if(this.get(i) == false)
			{
				return false;
			}
		}
		return true;
	}
/*	public boolean shareSomeLabels(IndexingBitSet ibs)
	{
		IndexingBitSet clone = (IndexingBitSet) ibs.clone();
		clone.andNot(this);
		if(clone.isEmpty())
			return false;
		else
			return true;
	}
*/

	public boolean hasNotTheSameLabelsAs(IndexingBitSet ibs) {
		for(int i = ibs.nextSetBit(0); i >= 0; i = ibs.nextSetBit(i+1))
		{
			if(this.get(i) == true)
			{
				return false;
			}
		}
		return true;
	}

	
	
}
