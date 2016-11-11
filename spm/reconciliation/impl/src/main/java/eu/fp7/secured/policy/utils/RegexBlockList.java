/*******************************************************************************
 * Copyright (c) 2015 Politecnico di Torino.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     TorSec - SECURED Team - initial API and implementation
 ******************************************************************************/
package eu.fp7.secured.policy.utils;

import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class RegexBlockList.
 */
public class RegexBlockList implements BlockList{
	
	/** The list. */
	List<Block> list;
	
	/** The base. */
	RegExpSelector base;
	
	/**
	 * Instantiates a new regex block list.
	 *
	 * @param s the s
	 */
	public RegexBlockList(RegExpSelector s){
		this.base = (RegExpSelector) s.selectorClone();
		list = new LinkedList<Block>();
		list.add(new RegexBlock(s));
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#insert(eu.fp7.secured.rule.selector.Selector, int)
	 */
	@Override
	public boolean insert(Selector s, int index) throws UnsupportedSelectorException {
		if(s == null){
			for(Block b:list){
				b.getBs().set(index);
			}
			return true;
		}
		
		RegExpSelector to_insert;
		RegExpSelector to_insert_negated;
		if(base.isIntersecting(s)){
			to_insert = (RegExpSelector) s.selectorClone();
			to_insert.intersection(base);
			to_insert_negated = (RegExpSelector) s.selectorClone();
			to_insert_negated.complement();
			to_insert_negated.intersection(base);
		}
		else{
			return false;
		}
		
		List<Block> block_to_insert = new LinkedList<Block>();
		for(Block rb:list){

			RegexBlock r = (RegexBlock) rb;
			
			boolean rint,rintneg;
			rintneg = r.getSelector().isIntersecting(to_insert_negated);
			rint = r.getSelector().isIntersecting(to_insert);
			
			if(rint==true && rintneg==false){ // s interseca un blocco interamente, lascio il blocco, aggiorno il BS
				r.getBs().set(index);
				continue;
			}
			
//			if(rint==false && rintneg==true) // s-negato interseca un blocco interamente, non faccio niente, lascio il blocco, non aggiorno il bs
//				continue; 
			
			if(rint==true && rintneg==true){ // interseca sia s che s-negato, devo dividere il blocco in due = ne aggiungo uno e restringo quello che c'�
				RegExpSelector clone = (RegExpSelector) to_insert_negated.selectorClone();
				clone.intersection(r.getSelector());
				RegexBlock cloneb = new RegexBlock(clone);
				cloneb.setBs((BitSet)r.getBs().clone());
				block_to_insert.add(cloneb);
				
				r.getSelector().intersection(to_insert);
				r.getBs().set(index);
			}

		}
		list.addAll(block_to_insert);
		
		return true;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#getBlocks()
	 */
	@Override
	public List<Block> getBlocks() {
		return Collections.unmodifiableList(list);
	}

	/**
	 * Prints the blocks.
	 */
	public void printBlocks() {
		for(Block b:list){
			RegexBlock rb = (RegexBlock) b;
			System.out.println(rb.getSelector().toString()+":"+rb.getBs());
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#atLeastOneLabel()
	 */
	@Override
	public boolean atLeastOneLabel() {
		for(Block b:list){
			if(b.getBs().isEmpty())
				return false;
		}
		
		return true;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#getBlocksAsSelectors()
	 */
	@Override
	public List<Selector> getBlocksAsSelectors() {
		
		List<Selector> selectors = new LinkedList<Selector>(); 
		
		for(Block b:this.list){
			selectors.add(((RegexBlock) b).getSelector());
		}
		
		
		return selectors;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#getBlocksAndBitSets()
	 */
	@Override
	public HashMap<Selector, BitSet> getBlocksAndBitSets() {
		
		
		HashMap<Selector, BitSet> selectors = new HashMap<Selector, BitSet>();
		
		for(Block b:this.list){
			selectors.put(((RegexBlock) b).getSelector(),b.getBs());
		}
		
		
		
		return null;
	}


	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.utils.BlockList#getBitSet(int)
	 */
	@Override
	public BitSet getBitSet(int index) {
		BitSet bitSet = new BitSet();
		
		for(Block b:list){
			if(b.getBs().get(index)){
				bitSet.or(b.getBs());
			}
		}
		
		return bitSet;
	}
	
}
