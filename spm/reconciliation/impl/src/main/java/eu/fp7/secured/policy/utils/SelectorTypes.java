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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.StringTokenizer;

import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class SelectorTypes.
 */
public class SelectorTypes {

	/** The selector types. */
	private LinkedHashMap<String, Selector> selectorTypes;

	/**
	 * Instantiates a new selector types.
	 */
	public SelectorTypes() {
		selectorTypes = new LinkedHashMap<String, Selector>();
	}

	/**
	 * Gets the all selector types.
	 *
	 * @return the all selector types
	 */
	public LinkedHashMap<String, Selector> getAllSelectorTypes() {
		return selectorTypes;
	}

	/**
	 * Gets the selector type.
	 *
	 * @param selectorType the selector type
	 * @return the selector type
	 */
	public Selector getSelectorType(String selectorType) {
		return selectorTypes.get(selectorType).selectorClone();
	}

	/**
	 * Adds the selector type.
	 *
	 * @param selectorType the selector type
	 * @param selector the selector
	 */
	public void addSelectorType(String selectorType, Selector selector) {
		Selector s = selector.selectorClone();
		s.empty();
		selectorTypes.put(selectorType, s);
	}

	/**
	 * Adds the selector types.
	 *
	 * @param input the input
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws ClassNotFoundException the class not found exception
	 * @throws SecurityException the security exception
	 * @throws NoSuchMethodException the no such method exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws InstantiationException the instantiation exception
	 * @throws IllegalAccessException the illegal access exception
	 * @throws InvocationTargetException the invocation target exception
	 */
	public void addSelectorTypes(InputStream input) throws IOException, ClassNotFoundException, SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {

		String selectorName;
		String selectorType;
		Selector s;

		BufferedReader br = new BufferedReader(new InputStreamReader(input));

		String str = null;
		str = br.readLine();

		while (str != null) {

			StringTokenizer st = new StringTokenizer(str, ":");

			if (st.hasMoreTokens()) {
				selectorName = st.nextToken();
				selectorType = null;
				if (st.hasMoreTokens()) {
					selectorType = st.nextToken();
				} else {
					throw new IOException("Error In configuration file: ");
				}

				Thread thread = Thread.currentThread();
				ClassLoader loader = thread.getContextClassLoader();
				thread.setContextClassLoader(this.getClass().getClassLoader());
				Class selectorClass = null;
				try {
					ClassLoader cloader = Thread.currentThread().getContextClassLoader();
					selectorClass = cloader.loadClass(selectorType);
				} finally {
					thread.setContextClassLoader(loader);
				}

				Constructor resConstructor = null;
				resConstructor = selectorClass.getConstructor(new Class[0]);
				s = (Selector) resConstructor.newInstance(new Object[0]);

				
				selectorTypes.put(selectorName, s);
			}

			str = br.readLine();
		}

		br.close();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();

		for (String sel : selectorTypes.keySet()) {
			sb.append(sel + selectorTypes.get(sel).getClass().getName() + "\n");
		}

		return sb.toString();
	}

	/**
	 * Gets the selector names.
	 *
	 * @return the selector names
	 */
	public String[] getSelectorNames() {
		return selectorTypes.keySet().toArray(new String[selectorTypes.size()]);
	}
}
