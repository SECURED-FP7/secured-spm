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

public class SelectorTypes {

	private LinkedHashMap<String, Selector> selectorTypes;

	public SelectorTypes() {
		selectorTypes = new LinkedHashMap<String, Selector>();
	}

	public LinkedHashMap<String, Selector> getAllSelectorTypes() {
		return selectorTypes;
	}

	public Selector getSelectorType(String selectorType) {
		return selectorTypes.get(selectorType).selectorClone();
	}

	public void addSelectorType(String selectorType, Selector selector) {
		Selector s = selector.selectorClone();
		s.empty();
		selectorTypes.put(selectorType, s);
	}

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

	public String toString() {
		StringBuffer sb = new StringBuffer();

		for (String sel : selectorTypes.keySet()) {
			sb.append(sel + selectorTypes.get(sel).getClass().getName() + "\n");
		}

		return sb.toString();
	}

	public String[] getSelectorNames() {
		return selectorTypes.keySet().toArray(new String[selectorTypes.size()]);
	}
}
