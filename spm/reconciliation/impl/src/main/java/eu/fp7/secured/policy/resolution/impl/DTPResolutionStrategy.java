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
package eu.fp7.secured.policy.resolution.impl;

import java.util.Collection;

import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Class DTPResolutionStrategy.
 */
public class DTPResolutionStrategy extends GenericConflictResolutionStrategy {
        
        /** The Constant label. */
        private static final String label = "Deny Take Precedence (DTP)";
        
        /** The Constant label_simple. */
        private static final String label_simple = "DTP";

        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
         */
        @Override
        public Action composeActions(GenericRule r1, GenericRule r2) throws InvalidActionException {
                Action a1 = r1.getAction();
                Action a2 = r2.getAction();
                
                if(a1 == FilteringAction.DENY){
                        if(a2 == FilteringAction.DENY || a2 == FilteringAction.ALLOW)
                                return FilteringAction.DENY;
                        else{
                                System.err.println("AZIONI:"+ a1 + "\n" + a2);
                                throw new InvalidActionException();
                        }
                }
                else if(a1 == FilteringAction.ALLOW)
                {
                        if(a2 == FilteringAction.DENY)
                                return FilteringAction.DENY;
                        else if(a2 == FilteringAction.ALLOW)
                                return FilteringAction.ALLOW;
                        else
                                throw new InvalidActionException();
                }
                else{
                        System.err.println("AZIONI:"+ a1 + "\n" + a2);
                        throw new InvalidActionException();
                }
        }
        
        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#composeActions(eu.fp7.secured.rule.impl.GenericRule[])
         */
        @Override
        public Action composeActions(GenericRule[] rules) throws InvalidActionException{
                boolean deny = false;
                for(GenericRule rule: rules){
                        Action a = rule.getAction();
                        if(a.equals(FilteringAction.DENY))
                                deny = true;
                        else if(a != FilteringAction.ALLOW)
                                throw new InvalidActionException();
                }
                if(deny) return FilteringAction.DENY;
                else return FilteringAction.ALLOW;
        }

        
       

        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#isActionEquivalent(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
         */
        @Override
        public boolean isActionEquivalent(GenericRule r1, GenericRule r2) {
                return r1.getAction() == r2.getAction();
        }

        

        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#compare(eu.fp7.secured.rule.impl.GenericRule, eu.fp7.secured.rule.impl.GenericRule)
         */
        @Override
        public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException {
                if(r1.getAction() == FilteringAction.DENY)
                        if(r2.getAction() == FilteringAction.ALLOW)
                                return ResolutionComparison.UNIVERSALLY_GREATER;
                        else
                                return ResolutionComparison.EQUIVALENT;
                else 
                        if(r2.getAction() == FilteringAction.DENY)
                                return ResolutionComparison.UNIVERSALLY_LESS;
                        else
                                return ResolutionComparison.EQUIVALENT;
        }


        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#cloneResolutionStrategy()
         */
        @Override
        public GenericConflictResolutionStrategy cloneResolutionStrategy() {
                return new DTPResolutionStrategy();
        }

        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#toString()
         */
        @Override
        public String toString(){
                return label;
        }
        
        /* (non-Javadoc)
         * @see eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy#toSimpleString()
         */
        @Override
    	public String toSimpleString() {
    		return label_simple;
    	}
}