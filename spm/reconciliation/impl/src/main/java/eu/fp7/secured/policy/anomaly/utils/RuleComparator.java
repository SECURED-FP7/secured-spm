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

import java.util.Comparator;

import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.impl.GenericRule;


/**
 * The Class RuleComparator.
 */
public class RuleComparator implements Comparator<GenericRule>{
	
	/** The resolver. */
	private GenericConflictResolutionStrategy resolver;
	
	/**
	 * Instantiates a new rule comparator.
	 *
	 * @param policy the policy
	 */
	public RuleComparator(Policy policy) {
		this.resolver = policy.getResolutionStrategy();
	}
	
	/* (non-Javadoc)
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	@Override
	public int compare(GenericRule r1, GenericRule r2) {
		ResolutionComparison comp = null;
		try {
			comp = resolver.compare(r1, r2);
		} catch (NoExternalDataException e) {
			e.printStackTrace();
		} catch (DuplicatedRuleException e) {
			e.printStackTrace();
		} catch (UnmanagedRuleException e) {
			e.printStackTrace();
		}
		if( comp == ResolutionComparison.UNIVERSALLY_LESS) return 1;
		else if(comp == ResolutionComparison.UNIVERSALLY_GREATER) return -1;
		else return 0;
	}
}