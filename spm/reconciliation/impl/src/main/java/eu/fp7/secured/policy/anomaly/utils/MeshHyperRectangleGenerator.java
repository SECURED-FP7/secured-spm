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
package eu.fp7.secured.policy.anomaly.utils;

import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.jws.Oneway;

import eu.fp7.secured.exception.policy.EmptySelectorException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.Block;
import eu.fp7.secured.policy.utils.BlockList;
import eu.fp7.secured.policy.utils.PointList;
import eu.fp7.secured.policy.utils.RegexBlockList;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.ExactMatchSelector;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.rule.selector.TotalOrderedSelector;


/**
 * The Class MeshHyperRectangleGenerator.
 */
public class MeshHyperRectangleGenerator {
        
        /** The block_list. */
        private BlockList [] block_list;
        
        /** The blocklists hm. */
        private HashMap<String, BlockList> blocklistsHM;
        
        /** The rule. */
        private GenericRule rule;
        
        /** The hiders. */
        private List<GenericRule> hiders;
        
        /** The inserted. */
        private int inserted; 
        
        /** The actual. */
        private int actual;
        
        /** The policy. */
        private Policy policy;
        
        /** The sel lab. */
        private String[] selLab;
        
        /** The hyper rectangles. */
        private HashMap<ConditionClause, BitSet> hyperRectangles;
        

        /**
         * Instantiates a new mesh hyper rectangle generator.
         *
         * @param r the r
         * @param policy the policy
         * @param selLab the sel lab
         * @throws Exception the exception
         */
        public MeshHyperRectangleGenerator(GenericRule r, Policy policy, String[] selLab) throws Exception {
//                if(!policy.getRuleSet().contains(r)){
//                        System.err.println("The base rule must be in the policy");
//                        throw new Exception();
//                }
                setRule(r);
                hiders = new LinkedList<GenericRule>();
                inserted = 0;
                actual = 0;
                this.policy = policy;
                this.hyperRectangles = new HashMap<ConditionClause, BitSet>();
                this.selLab = selLab;
                
        }
        
        /**
         * Sets the rule.
         *
         * @param r the new rule
         * @throws EmptySelectorException the empty selector exception
         * @throws UnsupportedSelectorException the unsupported selector exception
         */
        // prepares all the PointLists associated to the base rule selectors
        private void setRule(GenericRule r) throws EmptySelectorException, UnsupportedSelectorException{
                
                rule = r;
                
                blocklistsHM = new HashMap<String, BlockList>();
                try {
                        for(String keylabel: selLab){
                                Selector s = r.getConditionClause().get(keylabel);
                                if(s instanceof ExactMatchSelector)
                                	blocklistsHM.put(keylabel, new PointList(s,keylabel));
                                else if(s instanceof TotalOrderedSelector)
                                	blocklistsHM.put(keylabel, new PointList(s,keylabel));
                                else if(s instanceof RegExpSelector)
                                	blocklistsHM.put(keylabel, new RegexBlockList((RegExpSelector)s));
                        }
                } 
                catch (Exception e) {
                        e.printStackTrace();
                }               
        }
        

      /**
       * Gets the mesh hyper rectangles.
       *
       * @return the mesh hyper rectangles
       */
      //---------------------------------------------------------------
        public HashMap<ConditionClause, BitSet> getMeshHyperRectangles(){
                
           	prepareForMeshGeneration();
           	
            ConditionClause c_full = null;
            
            
            HashMap<ConditionClause, BitSet> hrBitsets = new HashMap<ConditionClause, BitSet>();
            HashMap<ConditionClause, BitSet> hrBitsetsTemp = new HashMap<ConditionClause, BitSet>(); 
            
            
            hrBitsets.put(c_full, new BitSet());
            boolean firstSelector = true;
            
            for(String s:rule.getConditionClause().getSelectorsNames()){
            	BlockList blocklist = blocklistsHM.get(s);
            	
            	HashMap<Selector, BitSet> selectors = blocklist.getBlocksAndBitSets();
            	
            	for(Selector sel: selectors.keySet()){
            		
            		for(ConditionClause c:hrBitsets.keySet()){
                		
                  		ConditionClause clone = c.conditionClauseClone();
                		try {
    						clone.setSelector(s, sel);
    					} catch (IncompatibleSelectorException e) {
    						e.printStackTrace();
    					}
                		
                		if(firstSelector){
                			hrBitsetsTemp.put(clone,selectors.get(sel));
                		}
                		else{
                			BitSet newbs = (BitSet) hrBitsets.get(c).clone();
                			newbs.and(selectors.get(sel));
                			hrBitsetsTemp.put(clone,newbs);
                		}
            		}
            	}
            	
            	hrBitsets.clear();
            	hrBitsets.putAll(hrBitsetsTemp);
            	hrBitsetsTemp.clear();
            	
            }
             

            hyperRectangles = hrBitsets;
            
            
            return hyperRectangles;
            
        }
        
                
        
        //--------------------------------------------------------------
//        private boolean recursive_verification(int n, BitSet base)
//        {       
//                if(n == block_list.length-1){
//                        //System.out.println("-"+ (n+1) + ":");
//                        return verifyAllPoints(block_list[n], base);
//                }
//                try{
//                for(Block p: (List<Block>)block_list[n].getBlocks())
//                {
//                        if(!base.intersects(p.getBs())){
//                                //TODO: verificare se equals o == funziona sulle azioni
//                                if(!this.policy.getDefaultAction().equals(rule.getAction())){ 
//                                        return false; 
//                                }
////                                else //migliora performance ma e' da verificare
////                               {continue;}
//                        }
//                        else
//                        {
//                                BitSet bs_new = ((BitSet) base.clone());
//                                bs_new.and(p.getBs());
//                                //System.out.println("-"+(n+1)+":"+bs_new);
//                                if(!recursive_verification(n+1, bs_new))
//                                {
//                                        return false;
//                                }
//                        }
//                }
//                }catch(Exception e){
//                        System.err.println(rule);
//                        System.err.println(hiders);
//                        e.printStackTrace();
//                }
//                return true;
//                
//
//        }
        
        
        /**
         * Verify all points.
         *
         * @param list the list
         * @param bs the bs
         * @return true, if successful
         */
        //      --------------------------------------------------------------
        private boolean verifyAllPoints(BlockList list, BitSet bs)
        {
                for(Block p:(List<Block>)list.getBlocks())
                {
                        BitSet bs_new = ((BitSet) bs.clone());
                        bs_new.and(p.getBs());
                        if(!p.getBs().intersects(bs))
                        {
                                if(!this.policy.getDefaultAction().equals(rule.getAction())){
//                                        return true;
//                                }
//                                else{
                                        return false; 
                                }
                        }
                        
                        // se sono qui vuol dire che l'intersezione tra bs � non vuota
                        
                        try {
                        	// 
                        	Collection<GenericRule> remaining_rules = getRulesByBS(bs_new);
                                if(policy.getResolutionStrategy().composeActions(remaining_rules) != 
                                                policy.getResolutionStrategy().composeActions(remaining_rules,this.rule)){
//                                        return true;
//                                }
//                                else{
                                        return false;
                                }
                        } catch (NoExternalDataException e) {
                                e.printStackTrace();
                        } catch (InvalidActionException e) {
                                e.printStackTrace();
                        }
                }

                
                return true;
                
        }
        
        
        /**
         * Gets the rules by bs.
         *
         * @param bs the bs
         * @return the rules by bs
         */
        private Collection<GenericRule> getRulesByBS(BitSet bs)
        {
        	Set<GenericRule> set = new HashSet<GenericRule>();
        	for(int i=bs.nextSetBit(0); i>=0; i=bs.nextSetBit(i+1)) {
        		set.add(hiders.get(i));
        	}
        	
        	return set;
        }
        
/* (non-Javadoc)
 * @see java.lang.Object#toString()
 */
//----------------------------------------------------- 
        @Override
        public String toString()
        {       int i = 0;
                String s = "";
                for(BlockList l:block_list)
                {
                        s +=  "Selector " + (i++)+"\n" +l.toString()+"\n";
                        //s+= "Full: "+l.isFull()+"\n";
                }
                return s;
        }

      /**
       * Prepare for mesh generation.
       */
      //-----------------------------------------------------
        private void prepareForMeshGeneration() {
                int index =0;
                try {
                        for(GenericRule r: policy.getRuleSet())
                        {
                        	if(!r.equals(rule))
                                        addChildrenRule(r, index++);
                        }
                } catch (Exception e) {
                        e.printStackTrace();
                }
        }

//      --------------------------------------------------------------- 
/**
 * Adds the children rule.
 *
 * @param r the r
 * @param index the index
 * @throws UnsupportedSelectorException the unsupported selector exception
 */
//  updates all the PointLists with intersecting rules
        private void addChildrenRule(GenericRule r, int index) throws UnsupportedSelectorException
        {
                inserted++;
                
                hiders.add(r);
                if(!rule.isIntersecting(r))
                        return;
                Selector srule,s;
                try {
                        HashSet<String> selLab = policy.getSelectorNames();
                        for(String keylabel: selLab){
                                srule = this.rule.getConditionClause().get(keylabel);
                                s = r.getConditionClause().get(keylabel).selectorClone();
                                if(srule!=null){
                                        s.intersection(srule);
                                }
                                if(s.isEmpty()) //TODO: probabilmente non necessario
                                        return;
                                        
                                BlockList pl = blocklistsHM.get(keylabel);
                                pl.insert(s, index);
                        }
                        
                } 
                catch (Exception e) {
                        e.printStackTrace();
                }               
                
                actual++;               
        }       

        /**
         * Gets the actual.
         *
         * @return the actual
         */
        public  int getActual() {
                return actual;
        }

        /**
         * Gets the inserted.
         *
         * @return the inserted
         */
        public  int getInserted() {
                return inserted;
        }

        
//        public void print_ep(){
//                for(BlockList p: block_list){
//                        System.out.println("points:  " + p.getBlocks());
//                        System.out.println("Epoints: " + p.getBlocks());
//                }
//        }       
}