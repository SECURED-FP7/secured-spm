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
import java.util.Random;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.selector.impl.IpSelector;
import eu.fp7.secured.selector.impl.PortSelector;
import eu.fp7.secured.selector.impl.ProtocolIDSelector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;

/**
 * The Class SelectorGenerator.
 */
public class SelectorGenerator {

	/** The random. */
	private static Random RANDOM = new Random(System.currentTimeMillis());

	/**
	 * Gets the IP selector list.
	 *
	 * @param startIP the start ip
	 * @param endIP the end ip
	 * @param maxIPRanges the max ip ranges
	 * @param IPRangeWidth the IP range width
	 * @return the IP selector list
	 */
	public static IpSelector getIPSelectorList(long startIP, long endIP, int maxIPRanges, int IPRangeWidth) {
		int rangeNumber;

		IpSelector ipSelector = new IpSelector();

		long minIP, maxIP;

		rangeNumber = RANDOM.nextInt(maxIPRanges);

		for (int j = 0; j <= rangeNumber; j++) {
			minIP = startIP + Math.abs(RANDOM.nextLong() % ((endIP-startIP) + 1));
			maxIP = minIP + Math.abs(RANDOM.nextLong() % (IPRangeWidth));

			if (maxIP > endIP)
				maxIP = endIP;

			ipSelector.addRange(minIP, maxIP);
		}

		return ipSelector;
	}

	/**
	 * Gets the protocol id list.
	 *
	 * @param maxProtocolID the max protocol id
	 * @return the protocol id list
	 */
	public static ProtocolIDSelector getProtocolIDList(int maxProtocolID) {

		int maxValue = ProtocolIDSelector.getMAX_VALUE();
		int rangeNumber = RANDOM.nextInt(maxProtocolID);
		
		ProtocolIDSelector protocolIDSelector = new ProtocolIDSelector();
		for (int j = 0; j <= rangeNumber; j++) {
			int value = RANDOM.nextInt(maxValue);
			try {
				protocolIDSelector.addRange(value);
			} catch (InvalidRangeException e) {
				j--;
				e.printStackTrace();
			}
		}

		return protocolIDSelector;
	}

	/**
	 * Gets the port selector list.
	 *
	 * @param maxPortRanges the max port ranges
	 * @param PortRangeWidth the port range width
	 * @return the port selector list
	 */
	public static PortSelector getPortSelectorList(int maxPortRanges, int PortRangeWidth) {
		int maxValue, rangeNumber;
		maxValue = PortSelector.getMaxPort();

		int minPort, maxPort;

		rangeNumber = RANDOM.nextInt(maxPortRanges);

		PortSelector portSelector = new PortSelector();
		for (int j = 0; j <= rangeNumber; j++) {
			minPort = RANDOM.nextInt(maxValue);
			maxPort = minPort + RANDOM.nextInt(PortRangeWidth);
			if (maxPort > maxValue)
				maxPort = maxValue;

			try {
				portSelector.addRange(minPort, maxPort);
			} catch (InvalidRangeException e) {
				j--;
			}
		}

		return portSelector;

	}

	/**
	 * Gets the regex selelector list.
	 *
	 * @param NumSel the num sel
	 * @return the regex selelector list
	 */
	public static StandardRegExpSelector getRegexSelelectorList(int NumSel) {

		String[] machine = { "www[a-zA-Z]*", "ww[a-zA-Z]*", "w[a-zA-Z]*", "[a-zA-Z]*" };
		String[] domain = { "c[a-zA-Z]*", "co[a-zA-Z]*", "com[a-zA-Z]*", "[a-zA-Z]*", "[a-zA-Z]*" };
		String[] subdomain = { "polito[a-zA-Z]*", "poli[a-zA-Z]*", "po[a-zA-Z]*", "p[a-zA-Z]*", "[a-zA-Z]*" };

		StandardRegExpSelector standardRegExpSelector = new StandardRegExpSelector();

		String regex = "";

		if (RANDOM.nextInt(10) < 5) {
			regex = ".*";
		} else {
			regex += machine[RANDOM.nextInt(machine.length)] + "\\.";
			regex += subdomain[RANDOM.nextInt(subdomain.length)] + "\\.";
			regex += domain[RANDOM.nextInt(domain.length)];
		}

		standardRegExpSelector.addRange(regex);
		

		return standardRegExpSelector;
	}

}
