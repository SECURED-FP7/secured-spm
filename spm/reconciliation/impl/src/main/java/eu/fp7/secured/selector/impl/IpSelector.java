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
package eu.fp7.secured.selector.impl;

import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.policy.utils.IpAddressManagement;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class IpSelector.
 */
public class IpSelector extends TotalOrderedSelectorImpl {

	/** The ranges. */
	private long[] ranges;
	
	/** The r_copy. */
	private long[] r_copy;
	
	/** The min. */
	private static String min = "0.0.0.0";
	
	/** The max. */
	private static String max = "255.255.255.255";
	
	/** The min_l. */
	private static long min_l = 0L;
	
	/** The max_l. */
	private static long max_l = 4294967295L;

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isPoint()
	 */
	public boolean isPoint() {
		if (ranges != null) {
			if (ranges[0] == ranges[1])
				if (ranges[0] != -2)
					if (ranges.length > 2) {
						if (ranges[3] < 0)
							return true;
					} else
						return true;

		}
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	public long length() {
		long sum = 0;
		boolean toggle = true;
		long prev = 0;
		for (long r : ranges) {
			if (toggle) {
				prev = r;
				if (prev < 0)
					break;
			} else {
				sum += r - prev + 1;
			}
			toggle = !toggle;
		}
		return sum;
	}

	/**
	 * Initialize.
	 *
	 * @param array the array
	 */
	private void initialize(long[] array) {
		for (int i = 0; i < array.length; i++)
			array[i] = -2;
	}

	/**
	 * Adds the range.
	 *
	 * @param Ip the ip
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws InvalidNetException the invalid net exception
	 */
	/*
	 * 
	 */
	public void addRange(String Ip) throws InvalidIpAddressException, InvalidRangeException, InvalidNetException {
		IpAddressManagement ipam = IpAddressManagement.getInstance();
		// if (ipam.getNetNumber(Ip)!=-1)
		// throw new InvalidIpAddressException();
		if (Ip.contains("-"))
			addRange(Ip.split("-")[0], Ip.split("-")[1]);
		else if (Ip.contains("\\") || Ip.contains("/")) {
			if (Ip.contains("\\"))
				addRange(Ip.split("\\")[0], Integer.valueOf(Ip.split("\\")[1]));
			if (Ip.contains("/"))
				addRange(Ip.split("/")[0], Integer.valueOf(Ip.split("/")[1]));
		} else {

			long s = ipam.toLong(Ip);
			if (s < min_l || s > max_l)
				throw new InvalidRangeException();
			addRange(s, s);
		}

	}

	/**
	 * Adds the range.
	 *
	 * @param IpStart the ip start
	 * @param IpEnd the ip end
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 */
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.polito.ruleManagement.selector.TotalOrderedSelector#addRange(java
	 * .lang.Object, java.lang.Object)
	 */
	public void addRange(String IpStart, String IpEnd) throws InvalidIpAddressException, InvalidRangeException {
		IpAddressManagement ipam = IpAddressManagement.getInstance();

		int net = ipam.getNetNumber(IpEnd);
		if (net == -1) {
			int n;
			try {
				n = Integer.parseInt(IpEnd);
				addRange(IpStart, n);
				return;
			} catch (NumberFormatException e) {
			} catch (InvalidNetException ex) {
				throw new InvalidIpAddressException();
			}
			long s = ipam.toLong(IpStart);
			long e = ipam.toLong(IpEnd);
			if (s < min_l || e > max_l || s > e)
				throw new InvalidRangeException();
			addRange(s, e);
		} else {
			long[] r = ipam.parseNet(IpStart, net);
			if (r[0] < min_l || r[1] > max_l || r[0] > r[1])
				throw new InvalidRangeException();
			addRange(r[0], r[1]);
		}

	}

	/**
	 * Adds the range.
	 *
	 * @param IpStart the ip start
	 * @param net the net
	 * @throws InvalidNetException the invalid net exception
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String IpStart, Integer net) throws InvalidNetException, InvalidRangeException {
		if (net < 0 || net > 32)
			throw new InvalidNetException();

		IpAddressManagement ipam = IpAddressManagement.getInstance();
		long[] r = ipam.parseNet(IpStart, net);
		if (r[0] < min_l || r[1] > max_l || r[0] > r[1])
			throw new InvalidRangeException();
		addRange(r[0], r[1]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.polito.ruleManagement.selector.TotalOrderedSelector#addRange(java
	 * .lang.Object, java.lang.Object)
	 */
	public void addRange(Object Start, Object End) throws InvalidRangeException {
		if (Start instanceof java.lang.String && End instanceof java.lang.String)
			try {
				addRange((String) Start, (String) End);
			} catch (InvalidIpAddressException e) {
				e.printStackTrace();
				throw new InvalidRangeException();
			}
		else if (Start instanceof java.lang.String && End instanceof Integer)
			try {
				addRange((String) Start, (Integer) End);
			} catch (InvalidRangeException e) {
				e.printStackTrace();
				throw new InvalidRangeException();
			} catch (InvalidNetException e) {
				e.printStackTrace();
				throw new InvalidRangeException();
			}
		else
			throw new InvalidRangeException();

	}

	/**
	 * Copy.
	 */
	private void copy() {
		for (int i = 0; i < ranges.length; i++)
			r_copy[i] = ranges[i];
	}

	/**
	 * Adds the range.
	 *
	 * @param start the start
	 * @param end the end
	 */
	public void addRange(long start, long end) {
		if (this.isEmpty()) {
			ranges = new long[2];
			ranges[0] = start;
			ranges[1] = end;
		} else {
			int size = ranges.length;
			r_copy = new long[size];
			copy();

			if (size > 2 && ranges[size - 1] == -2)
				ranges = new long[size];
			else
				ranges = new long[size + 2];
			initialize(ranges);

			int i = 0, index = 0;
			boolean done = false;

			while (i < size && !done) {
				if (start >= r_copy[i] && end <= r_copy[i + 1]) {
					done = true;
				} else if (start <= r_copy[i] && end >= r_copy[i + 1]) {
					i += 2;
				} else if (end < r_copy[i] && !(end == r_copy[i] - 1)) {
					ranges[index] = start;
					ranges[++index] = end;
					index++;
					//i += 2;
					done = true;
				} else if ((end >= r_copy[i] || end + 1 == r_copy[i]) && start < r_copy[i]) {
					ranges[index] = start;
					ranges[++index] = r_copy[i + 1];
					i += 2;
					index++;
					done = true;
				} else if (start <= r_copy[i + 1] || start - 1 == r_copy[i + 1]) {
					start = r_copy[i];
					i += 2;
				} else if (start > r_copy[i + 1]) {
					if (!(i > 0 && r_copy[i] == -2)) {
						ranges[index] = r_copy[i];
						ranges[++index] = r_copy[i + 1];
						index++;
					}
					i += 2;
				}
			}
			if (done) {
				for (; i < size; i++) {
					ranges[index] = r_copy[i];
					ranges[++index] = r_copy[++i];
					index++;
				}
			} else {
				ranges[index] = start;
				ranges[++index] = end;
			}
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	public void complement() {
		if (this.isFull()) {
			empty();
			return;
		}

		if (this.isEmpty()) {
			this.addRange(min_l, max_l);
			return;
		}

		int sub = 0;

		if (this.isEmpty()) {
			ranges = new long[2];
			ranges[0] = min_l;
			ranges[1] = max_l;
		} else {
			int size = ranges.length;
			r_copy = new long[size];
			copy();
			if (size > 2 && ranges[size - 1] == -2)
				ranges = new long[size];
			else
				ranges = new long[size + 2];
			initialize(ranges);
			int index = 0;
			if (r_copy[0] != -2 && r_copy[0] != 0) {
				ranges[0] = 0;
				ranges[1] = r_copy[0] - 1;
				index += 2;
			}
			int i = 1;
			for (; i < size - 1; i++) {
				ranges[index] = r_copy[i] + 1;
				if (r_copy[++i] != -2)
					ranges[++index] = r_copy[i] - 1;
				else {
					ranges[++index] = max_l;
					r_copy[i] = max_l;
					break;
				}
				index++;
			}
			if (r_copy[i] < max_l) {
				ranges[index] = r_copy[i] + 1;
				ranges[++index] = max_l;
			}
		}

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#empty()
	 */
	public void empty() {
		ranges = null;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#intersection(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void intersection(Selector s) throws IllegalArgumentException {
		if (!(s instanceof IpSelector))
			throw new IllegalArgumentException();

		if (isEmpty() || s.isFull())
			return;

		if (isFull()) {
			ranges = ((IpSelector) s).ranges.clone();
			return;
		}

		if (s.isEmpty()) {
			empty();
			return;
		}

		int index = ranges.length + ((IpSelector) s).ranges.length;
		r_copy = new long[index];
		initialize(r_copy);
		index = 0;

		long[] external = ((IpSelector) s).ranges;
		int ex_size = external.length;
		int ac_size = ranges.length;

		boolean done = false;
		int pos = 0, pos_a = 0;

		while (!done) {
			if (external[pos + 1] < ranges[pos_a]) {
				if ((pos + 2) < ex_size && external[pos + 2] != -2)
					pos += 2;
				else
					done = true;
			} else if (external[pos] > ranges[pos_a + 1]) {
				if ((pos_a + 2) < ac_size && ranges[pos_a + 2] != -2)
					pos_a += 2;
				else
					done = true;
			} else {
				long temp_s, temp_e;
				if (ranges[pos_a] > external[pos])
					temp_s = ranges[pos_a];
				else
					temp_s = external[pos];
				if (ranges[pos_a + 1] > external[pos + 1]) {
					temp_e = external[pos + 1];
					if ((pos + 2) < ex_size && external[pos + 2] != -2)
						pos += 2;
					else
						done = true;
				} else {
					temp_e = ranges[pos_a + 1];
					if ((pos_a + 2) < ac_size && ranges[pos_a + 2] != -2)
						pos_a += 2;
					else
						done = true;

				}
				r_copy[index] = temp_s;
				r_copy[++index] = temp_e;
				index++;
			}
		} // fine while

		int i = 2;
		boolean f = false;
		for (; i < r_copy.length && !f; i++)
			f = r_copy[i] == -2;

		if (f)
			ranges = new long[--i];
		else
			ranges = new long[i];

		initialize(ranges);
		for (int j = 0; j < i; j++) {
			ranges[j] = r_copy[j];
			ranges[++j] = r_copy[j];
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;

		if (s.isFull())
			return true;

		long[] si = ((IpSelector) s).ranges;

		int j = 0, i = 0, size = ranges.length;
		boolean done;

		long st, e;

		while (i < size && ranges[i] != -2) {
			done = false;
			while (j < si.length && si[j] != -2 && !done) {
				st = si[j];
				e = si[j + 1];
				if (st <= ranges[i] && e >= ranges[i + 1] && ranges[i] != -2)
					done = true;

				if (!done)
					j += 2;
			}
			if (!done)
				return false;
			i += 2;

		}

		// while (j < si.length && si[j]!=-2){
		// st = si[j];
		// e = si[++j];
		// done=false;
		// while (i<size && !done){
		// if (st<=ranges[i] && e>=ranges[i+1] && ranges[i]!=-2)
		// done=true;
		// i+=2;
		// }
		// j++;
		// if (!done)
		// return false;
		// }
		return true;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEmpty()
	 */
	public boolean isEmpty() {
		if (ranges == null)
			return true;
		if (ranges[0] == -2 && ranges[1] == -2)
			ranges = null;
		return ranges == null;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isIntersecting(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {

		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull() || s.isFull())
			return true;

		long[] external = ((IpSelector) s).ranges;

		int a_size = ranges.length;
		int ex_size = external.length;

		boolean done = false;
		int pos = 0, pos_a = 0;

		while (!done) {
			if (external[pos + 1] < ranges[pos_a]) {
				if ((pos + 2) < ex_size && external[pos + 2] != -2)
					pos += 2;
				else
					done = true;
			} else if (external[pos] > ranges[pos_a + 1]) {
				if ((pos_a + 2) < a_size && ranges[pos_a + 2] != -2)
					pos_a += 2;
				else
					done = true;
			} else
				return true;
		}

		return false;
	}

	/**
	 * Sets the minus.
	 *
	 * @param s the new minus
	 * @throws IllegalArgumentException the illegal argument exception
	 */
	public void setMinus(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return;

		if (s.isFull())
			this.empty();

		IpSelector s1 = (IpSelector) s.selectorClone();

		// if (!this.label.equalsIgnoreCase(s.getLabel()))
		// if(!s.getLabel().equals(""))
		// label.concat(" || "+s.getLabel());
		//
		// String nl = new String(label);

		s1.complement();
		intersection(s1);

		// label = nl;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;

		if (s.isEmpty())
			return false;
		else if (this.isFull() && s.isFull())
			return true;

		long[] temp = ((IpSelector) s).ranges;
		int size, t_size;
		size = ranges.length;
		t_size = temp.length;
		boolean eq = true;
		int i = 0;
		for (; i < size && i < t_size && eq && temp[i] != -2 && ranges[i] != -2; i++)
			eq = (temp[i] == ranges[i] && temp[++i] == ranges[i]);

		if (i >= size && i >= t_size)
			return eq;
		else if (i < size && i >= t_size) {
			if (ranges[i] == -2)
				return eq;
			else
				return false;
		} else if (i >= size && i < t_size) {
			if (temp[i] == -2)
				return eq;
			else
				return false;
		}

		return eq;

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isFull()
	 */
	public boolean isFull() {
		if (!this.isEmpty())
			return ranges[0] == min_l && ranges[1] == max_l;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	public Selector selectorClone() {
		IpSelector s = new IpSelector();
		if (!this.isEmpty()) {
			int size = ranges.length;
			s.ranges = new long[size];
			for (int i = 0; i < size; i++)
				s.ranges[i] = ranges[i];
		}

		return s;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	public void union(Selector s) throws IllegalArgumentException {
		if (this.isFull())
			return;

		if (!s.isEmpty()) {
			long[] temp = ((IpSelector) s).ranges;
			int t_size = temp.length;
			for (int i = 0; i < t_size; i++)
				this.addRange(temp[i], temp[++i]);
		}

	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		IpAddressManagement ipam = IpAddressManagement.getInstance();
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";

		String str = "";
		int size = ranges.length;
		for (int i = 0; i < size; i++) {
			if (ranges[i] == -2 && ranges[i + 1] == -2)
				break;
			str = str + "[" + ipam.getIpFromLong(ranges[i]) + " - " + ipam.getIpFromLong(ranges[++i]) + "] ";
		}
		return str;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	public String toSimpleString() {
		IpAddressManagement ipam = IpAddressManagement.getInstance();
		if (this.isEmpty())
			return "";
		if (this.isFull())
			return "*";

		StringBuffer sb = new StringBuffer();
		int size = ranges.length;
		for (int i = 0; i < size; i++) {
			if (ranges[i] == -2 && ranges[i + 1] == -2)
				break;
			if (i > 0)
				sb.append(",");
			if(ipam.getIpFromLong(ranges[i]).equals(ipam.getIpFromLong(ranges[i+1]))){
				sb.append(ipam.getIpFromLong(ranges[i++]));
			} else {
				sb.append(ipam.getIpFromLong(ranges[i]));
				sb.append("-");
				sb.append(ipam.getIpFromLong(ranges[++i]));
			}
//			sb.append(ipam.getIpFromLong(ranges[i]));
//			sb.append("-");
//			sb.append(ipam.getIpFromLong(ranges[++i]));
		}
		return sb.toString();
	}

	/**
	 * Gets the max.
	 *
	 * @return the max
	 */
	public static String getMax() {
		return max;
	}

	/**
	 * Gets the min.
	 *
	 * @return the min
	 */
	public static String getMin() {
		return min;
	}

	/**
	 * Gets the max long.
	 *
	 * @return the max long
	 */
	public static long getMaxLong() {
		return max_l;
	}

	/**
	 * Gets the min long.
	 *
	 * @return the min long
	 */
	public static long getMinLong() {
		return min_l;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;

		if (this.isFull())
			return false;

		if (s.isFull())
			return true;

		long[] si = ((IpSelector) s).ranges;

		int j = 0, i = 0, size = ranges.length;
		boolean done, atLeastOne = false;

		long st, e;
		while (j < si.length && si[j] != -2) {
			st = si[j];
			e = si[++j];
			done = false;
			while (i < size && !done) {
				if (st <= ranges[i] && ranges[i] != -2)
					if (e >= ranges[i + 1]) {
						if (!(ranges[i] == st && ranges[i + 1] == e))
							atLeastOne = true;
						done = true;
					}
				i += 2;
			}
			j++;
			if (!done)
				return false;
		}
		return atLeastOne;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.TotalOrderedSelector#getRanges()
	 */
	@Override
	public Long[] getRanges() {
		// TODO: chiedere a google come si fa a creare una lista di oggetti da
		// da tipi nativi
		Long[] ret = new Long[ranges.length];
		int i = 0;
		for (long n : ranges)
			ret[i++] = new Long(n);
		return ret;

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.TotalOrderedSelector#addRange(java.lang.Object)
	 */
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			try {
				addRange((String) Value);
			} catch (InvalidIpAddressException e) {
				e.printStackTrace();
				throw new InvalidRangeException();
			} catch (InvalidNetException e) {
				e.printStackTrace();
				throw new InvalidRangeException();
			}
		else
			throw new InvalidRangeException();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#getFirstAssignedValue()
	 */
	@Override
	public int getFirstAssignedValue() {
		if (ranges != null)
			if (ranges[0] > 0)
				return (int) ranges[0];

		return 0;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		ranges = new long[2];
		ranges[0] = min_l;
		ranges[1] = max_l;
	}

}
