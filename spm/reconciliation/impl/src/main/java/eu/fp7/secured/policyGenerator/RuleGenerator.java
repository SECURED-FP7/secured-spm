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

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.RegExpSelector;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.selector.impl.IpSelector;
import eu.fp7.secured.selector.impl.PortSelector;
import eu.fp7.secured.selector.impl.ProtocolIDSelector;


/**
 * The Class RuleGenerator.
 */
public class RuleGenerator {
	
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
	 * Instantiates a new rule generator.
	 *
	 * @param maxPortRanges the max port ranges
	 * @param PortRangeWidth the port range width
	 * @param maxIPRanges the max ip ranges
	 * @param IPRangeWidth the IP range width
	 * @param maxProtocolID the max protocol id
	 */
	public RuleGenerator(int maxPortRanges, int PortRangeWidth, int maxIPRanges, int IPRangeWidth, int maxProtocolID){
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
	 */
	public void setSourceStartIP(long startIP){
		this.sourceStartIP = startIP;
	}
	
	/**
	 * Sets the source end ip.
	 *
	 * @param endIP the new source end ip
	 */
	public void setSourceEndIP(long endIP){
		this.sourceEndIP = endIP;
	}
	
	/**
	 * Sets the destination start ip.
	 *
	 * @param startIP the new destination start ip
	 */
	public void setDestinationStartIP(long startIP){
		this.destinationStartIP = startIP;
	}
	
	/**
	 * Sets the destination end ip.
	 *
	 * @param endIP the new destination end ip
	 */
	public void setDestinationEndIP(long endIP){
		this.destinationEndIP = endIP;
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
	 * Gets the generic rule.
	 *
	 * @param action the action
	 * @param name the name
	 * @param selectorTypes the selector types
	 * @param selectorNames the selector names
	 * @return the generic rule
	 */
	public GenericRule getGenericRule(FilteringAction action, String name, SelectorTypes selectorTypes, String[] selectorNames){
		
		
		
		LinkedHashMap<String, Selector> selectors = new LinkedHashMap<String, Selector>();
		
		for(String s:selectorNames){
			
			if(selectorTypes.getSelectorType(s) instanceof IpSelector){
				if(s.equals("Source Address"))
					selectors.put(s, SelectorGenerator.getIPSelectorList(sourceStartIP, sourceEndIP, maxIPRanges, IPRangeWidth));
				if(s.equals("Destination Address"))
					selectors.put(s, SelectorGenerator.getIPSelectorList(destinationStartIP, destinationEndIP, maxIPRanges, IPRangeWidth));
			}
			
			if(selectorTypes.getSelectorType(s) instanceof PortSelector){
				selectors.put(s, SelectorGenerator.getPortSelectorList(maxPortRanges, PortRangeWidth));
			}
			
			if(selectorTypes.getSelectorType(s) instanceof ProtocolIDSelector){
				selectors.put(s, SelectorGenerator.getProtocolIDList(maxProtocolID));
			}
			
			if(selectorTypes.getSelectorType(s) instanceof RegExpSelector){
				selectors.put(s, SelectorGenerator.getRegexSelelectorList(1));
			}
		}
		
		
		ConditionClause conditionClause = new ConditionClause(selectors);
		
		
		HashSet<String> MSPLs = new HashSet<>();
		List<HSPL> HSPLs = new LinkedList<>();
		
		MSPLs.add(name);
		HSPL hspl = new HSPL();
		hspl.setHSPLId("HSPL"+name);
		hspl.setHSPLText("HSPL"+name);
		HSPLs.add(hspl);
		
		return new GenericRule(action, conditionClause, name, MSPLs, HSPLs);
		
	}

}
