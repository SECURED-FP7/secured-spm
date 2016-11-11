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
package eu.fp7.secured.policyGenerator;

import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.selector.impl.IpSelector;
import eu.fp7.secured.selector.impl.PortSelector;



/**
 * The Class FilteringPolicyGenerator.
 */
public class FilteringPolicyGenerator {
	
	/** The selector types. */
	private SelectorTypes selectorTypes;
	
	/**
	 * Instantiates a new filtering policy generator.
	 */
	public FilteringPolicyGenerator(){
		selectorTypes = new SelectorTypes();
		selectorTypes.addSelectorType("Source Address", new IpSelector());
		selectorTypes.addSelectorType("Destination Address", new IpSelector());
		selectorTypes.addSelectorType("Source Port", new PortSelector());
		selectorTypes.addSelectorType("Destination Port", new PortSelector());
	}

	/**
	 * Gets the selector types.
	 *
	 * @return the selector types
	 */
	public SelectorTypes getSelectorTypes(){
		return selectorTypes;
	}
	
	/**
	 * Gets the policy_4_20.
	 *
	 * @param num the num
	 * @return the policy_4_20
	 * @throws Exception the exception
	 */
	public Policy getPolicy_4_20(int num) throws Exception {
		PolicyGenerator generator = new PolicyGenerator(3, 190, 18, 50, 100);
		
		switch (num) {
		case 50:
			generator = new PolicyGenerator(3, 1000, 100, 50, 100);
			break;
		case 100:
			generator = new PolicyGenerator(3, 800, 50, 50, 100);
			break;
		case 250:
			generator = new PolicyGenerator(3, 700, 30, 50, 100);
			break;
		case 500:
			generator = new PolicyGenerator(3, 450, 20, 50, 100);
			break;
		case 750:
			generator = new PolicyGenerator(3, 400, 20, 50, 100);
			break;
		case 1000:
			generator = new PolicyGenerator(3, 310, 19, 50, 100);
			break;
		case 1500:
			generator = new PolicyGenerator(3, 250, 18, 50, 100);
			break;
		case 2000:
			generator = new PolicyGenerator(3, 210, 18, 50, 100);
			break;
		case 2500:
			generator = new PolicyGenerator(3, 190, 18, 50, 100);
			break;
		case 3000:
			generator = new PolicyGenerator(3, 180, 19, 50, 100);
			break;
		case 3500:
			generator = new PolicyGenerator(3, 170, 18, 50, 100);
			break;
		case 4000:
			generator = new PolicyGenerator(3, 160, 18, 50, 100);
			break;
		case 4500:
			generator = new PolicyGenerator(3, 150, 18, 50, 100);
			break;
		case 5000:
			generator = new PolicyGenerator(3, 140, 18, 50, 100);
			break;

		}


		generator.setSourceStartIP("10.0.0.0");
		generator.setSourceEndIP("10.0.0.255");

		generator.setDestinationStartIP("10.0.255.0");
		generator.setDestinationEndIP("10.0.255.255");

		

		Policy policy = generator.getPolicy(num, selectorTypes, selectorTypes.getSelectorNames(), FilteringAction.DENY, "testPolicy");

		

		return policy;
	}
	
	
	

}
