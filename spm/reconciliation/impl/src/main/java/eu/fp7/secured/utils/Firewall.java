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
package eu.fp7.secured.utils;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.selector.impl.IpSelector;


/**
 * The Class Firewall.
 */
public class Firewall {
	
	/** The connection_fw. */
	private HashMap<String, Firewall> connection_fw;
	
	/** The policy. */
	private Policy policy;
	
	/** The nat. */
	private Policy NAT;
	
	/** The vpn. */
	private Policy VPN;
	
	/** The routing. */
	private Policy routing;
	
	/** The interface_list. */
	private List<String> interface_list;
	
	/** The name. */
	private String name;
	
	/** The id. */
	private String id;
	
	/** The interfaces_id. */
	private List<String> interfaces_id;
	
	/** The fw_subnets. */
	private HashMap<String, IpSelector> fw_subnets;


	/**
	 * Instantiates a new firewall.
	 *
	 * @param interface_list the interface_list
	 * @param name the name
	 */
	public Firewall(List<String> interface_list, String name) {
		this.interface_list = interface_list;
		this.name = name;
		this.connection_fw = new HashMap<String, Firewall>();
	}

	/**
	 * Instantiates a new firewall.
	 *
	 * @param interface_list the interface_list
	 * @param name the name
	 * @param id the id
	 * @param interfaces_id the interfaces_id
	 */
	public Firewall(List<String> interface_list, String name, String id, List<String> interfaces_id) {
		this.interface_list = interface_list;
		this.name = name;
		this.connection_fw = new HashMap<String, Firewall>();
		this.id=id;
		this.interfaces_id=interfaces_id;
	}
	
	/**
	 * Adds the fw.
	 *
	 * @param interface_name the interface_name
	 * @param fw the fw
	 */
	public void addFW(String interface_name, Firewall fw){
		connection_fw.put(interface_name, fw);
	}
	
	/**
	 * Gets the policy.
	 *
	 * @return the policy
	 */
	public Policy getPolicy(){
		return policy;
	}
	
	/**
	 * Sets the policy.
	 *
	 * @param policy the new policy
	 */
	public void setPolicy(Policy policy){
		this.policy = policy;
	}
	
	/**
	 * Gets the nat.
	 *
	 * @return the nat
	 */
	public Policy getNAT(){
		return NAT;
	}
	
	/**
	 * Sets the nat.
	 *
	 * @param NAT the new nat
	 */
	public void setNAT(Policy NAT){
		this.NAT = NAT;
	}
	
	/**
	 * Gets the vpn.
	 *
	 * @return the vpn
	 */
	public Policy getVPN(){
		return VPN;
	}
	
	/**
	 * Sets the vpn.
	 *
	 * @param VPN the new vpn
	 */
	public void setVPN(Policy VPN){
		this.VPN = VPN;
	}
	
	/**
	 * Gets the routing.
	 *
	 * @return the routing
	 */
	public Policy getRouting() {
		return routing;
	}

	/**
	 * Sets the routing.
	 *
	 * @param routing the new routing
	 */
	public void setRouting(Policy routing) {
		this.routing = routing;
	}

	/**
	 * Gets the name.
	 *
	 * @return the name
	 */
	public String getName(){
		return name;
	}
	
	/**
	 * Gets the interfaces.
	 *
	 * @return the interfaces
	 */
	public List<String> getInterfaces(){
		return interface_list;
	}
	
	/**
	 * Gets the firewalls.
	 *
	 * @return the firewalls
	 */
	public Collection<Firewall> getFirewalls(){
		return connection_fw.values();
	}
	
	/**
	 * Gets the firewall.
	 *
	 * @param inter the inter
	 * @return the firewall
	 */
	public Firewall getFirewall(String inter){
		return connection_fw.get(inter);
	}

	/**
	 * Gets the id.
	 *
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * Sets the id.
	 *
	 * @param id the new id
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Gets the interfaces_id.
	 *
	 * @return the interfaces_id
	 */
	public List<String> getInterfaces_id() {
		return interfaces_id;
	}

	/**
	 * Sets the interfaces_id.
	 *
	 * @param interfaces_id the new interfaces_id
	 */
	public void setInterfaces_id(List<String> interfaces_id) {
		this.interfaces_id = interfaces_id;
	}

	/**
	 * Gets the interfaces_subnet.
	 *
	 * @return the interfaces_subnet
	 */
	public HashMap<String, IpSelector> getInterfaces_subnet() {
		return fw_subnets;
	}

	/**
	 * Sets the interfaces_subnet.
	 *
	 * @param interfaces_subnet the interfaces_subnet
	 */
	/*TODO public String getInterfaceNameFromSubnet(IpSelector i)
	{
		for(IpSelector i2: fw_subnets.keySet())
			if(i.)
	}*/
	public void setInterfaces_subnet(HashMap<String, IpSelector> interfaces_subnet) {
		this.fw_subnets = interfaces_subnet;
	}

	/**
	 * Gets the connection_fw.
	 *
	 * @return the connection_fw
	 */
	public HashMap<String, Firewall> getConnection_fw() {
		return connection_fw;
	}

	/**
	 * Sets the connection_fw.
	 *
	 * @param connection_fw the connection_fw
	 */
	public void setConnection_fw(HashMap<String, Firewall> connection_fw) {
		this.connection_fw = connection_fw;
	}
}
