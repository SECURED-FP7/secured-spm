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

import java.util.LinkedList;

import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.impl.PolicyImpl;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.policy.utils.IpAddressManagement;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.selector.impl.IpSelector;

/**
 * The Class PolicyGenerator.
 */
public class PolicyGenerator {
	
	/** The max port ranges. */
	private int maxPortRanges;
	
	/** The Port range width. */
	private int PortRangeWidth;
	
	/** The max ip ranges. */
	private int maxIPRanges;
	
	/** The IP range width. */
	private int IPRangeWidth;
	
	/** The max protocol id. */
	private int maxProtocolID;
	
	/** The source start ip. */
	private long sourceStartIP;
	
	/** The source end ip. */
	private long sourceEndIP;
	
	/** The destination start ip. */
	private long destinationStartIP;
	
	/** The destination end ip. */
	private long destinationEndIP;
	
	/**
	 * Instantiates a new policy generator.
	 *
	 * @param maxPortRanges the max port ranges
	 * @param PortRangeWidth the port range width
	 * @param maxIPRanges the max ip ranges
	 * @param IPRangeWidth the IP range width
	 * @param maxProtocolID the max protocol id
	 */
	public PolicyGenerator(int maxPortRanges, int PortRangeWidth, int maxIPRanges, int IPRangeWidth, int maxProtocolID){
		this.maxPortRanges = maxPortRanges;
		this.PortRangeWidth = PortRangeWidth;		
		this.maxIPRanges = maxIPRanges;
		this.IPRangeWidth = IPRangeWidth;
		this.maxProtocolID = maxProtocolID;
		this.sourceStartIP = 0;
		this.sourceEndIP = IpSelector.getMaxLong();
		this.destinationStartIP = 0;
		this.destinationEndIP = IpSelector.getMaxLong();
	}
	
	/**
	 * Sets the source start ip.
	 *
	 * @param startIP the new source start ip
	 * @throws InvalidIpAddressException the invalid ip address exception
	 */
	public void setSourceStartIP(String startIP) throws InvalidIpAddressException{
		this.sourceStartIP = IpAddressManagement.getInstance().toLong(startIP);
	}
	
	/**
	 * Sets the source end ip.
	 *
	 * @param endIP the new source end ip
	 * @throws InvalidIpAddressException the invalid ip address exception
	 */
	public void setSourceEndIP(String endIP) throws InvalidIpAddressException{
		this.sourceEndIP = IpAddressManagement.getInstance().toLong(endIP);
	}
	
	/**
	 * Sets the destination start ip.
	 *
	 * @param startIP the new destination start ip
	 * @throws InvalidIpAddressException the invalid ip address exception
	 */
	public void setDestinationStartIP(String startIP) throws InvalidIpAddressException{
		this.destinationStartIP = IpAddressManagement.getInstance().toLong(startIP);
	}
	
	/**
	 * Sets the destination end ip.
	 *
	 * @param endIP the new destination end ip
	 * @throws InvalidIpAddressException the invalid ip address exception
	 */
	public void setDestinationEndIP(String endIP) throws InvalidIpAddressException{
		this.destinationEndIP = IpAddressManagement.getInstance().toLong(endIP);
	}
	
	/**
	 * Gets the policy.
	 *
	 * @param ruleNum the rule num
	 * @param selectorTypes the selector types
	 * @param selectorNames the selector names
	 * @param defaultAction the default action
	 * @param name the name
	 * @return the policy
	 */
	public Policy getPolicy(int ruleNum, SelectorTypes selectorTypes, String[] selectorNames, Action defaultAction, String name){
		
		PolicyImpl policy = new PolicyImpl(new FMRResolutionStrategy(), defaultAction, new LinkedList<Capability>(), name, "GENERATOR");
		RuleGenerator ruleGenerator = new RuleGenerator(maxPortRanges, PortRangeWidth, maxIPRanges, IPRangeWidth, maxProtocolID);
		ruleGenerator.setSourceStartIP(sourceStartIP);
		ruleGenerator.setSourceEndIP(sourceEndIP);
		ruleGenerator.setDestinationStartIP(destinationStartIP);
		ruleGenerator.setDestinationEndIP(destinationEndIP);
		for(int i=0; i<ruleNum; i++){
			GenericRule rule = ruleGenerator.getGenericRule(FilteringAction.ALLOW, "R"+i, selectorTypes, selectorNames);
			try {
				policy.insertRule(rule, i);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return policy;
	}
	

	
	
}