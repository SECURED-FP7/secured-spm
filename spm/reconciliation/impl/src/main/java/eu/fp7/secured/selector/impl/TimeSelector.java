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
import java.util.StringTokenizer;

import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class TimeSelector.
 */
public class TimeSelector extends TotalOrderedSelectorImpl {

	/** The ranges. */
	private int[] ranges;
	
	/** The r_copy. */
	private int[] r_copy;
	
	/** The l. */
	private List<Long> l;
	
	/** The min time. */
	private static int minTime = 0;
	
	/** The max time. */
	private static int maxTime = 1439;

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

	/**
	 * Convert.
	 *
	 * @param timeS the time s
	 * @param timeE the time e
	 * @return the string
	 */
	private static String convert(int timeS, int timeE) {
		if (timeS < minTime || timeS > maxTime)
			return "TimeSelector.convert(int): Value " + timeS + " not valid";

		if (timeE < minTime || timeE > maxTime)
			return "TimeSelector.convert(int): Value " + timeE + " not valid";

		int minS = timeS % (24 * 60);
		int hourS = minS / 60;
		minS = minS % 60;

		int minE = timeE % (25 * 60);
		int hourE = minE / 60;
		minE = minE % 60;

		StringBuffer sb = new StringBuffer();
		if (hourS < 10)
			sb.append("0");
		sb.append(hourS);
		sb.append(":");
		if (minS < 10)
			sb.append("0");
		sb.append(minS);
		sb.append("-");
		if (hourE < 10)
			sb.append("0");
		sb.append(hourE);
		sb.append(":");
		if (minE < 10)
			sb.append("0");
		sb.append(minE);

		return sb.toString();

	}

	/**
	 * Convert.
	 *
	 * @param time the time
	 * @return the int[]
	 * @throws InvalidRangeException the invalid range exception
	 */
	private static int[] convert(String time) throws InvalidRangeException {

		int result[] = new int[2];

		StringTokenizer st2 = new StringTokenizer(time, "-");

		StringTokenizer st3 = new StringTokenizer(st2.nextToken(), ":");
		int sh = Integer.parseInt(st3.nextToken());
		int sm = Integer.parseInt(st3.nextToken());

		if (st2.hasMoreTokens()) {
			st3 = new StringTokenizer(st2.nextToken(), ":");
			int eh = Integer.parseInt(st3.nextToken());
			int em = Integer.parseInt(st3.nextToken());

			result[1] = eh * 60 + em;
		} else {
			result[1] = -1;
		}

		result[0] = sh * 60 + sm;

		return result;
	}

	/**
	 * Inizialize.
	 *
	 * @param array the array
	 */
	private void inizialize(int[] array) {
		for (int i = 0; i < array.length; i++)
			array[i] = -2;
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
	 * @throws InvalidRangeException the invalid range exception
	 */
	private void addRange(int start, int end) throws InvalidRangeException {
		if (start < minTime || end > maxTime || start > end)
			throw new InvalidRangeException();

		if (this.isEmpty()) {
			ranges = new int[2];
			ranges[0] = start;
			ranges[1] = end;
		} else {
			int size = ranges.length;
			r_copy = new int[size];
			copy();

			if (size > 2 && ranges[size - 1] == -2)
				ranges = new int[size];
			else
				ranges = new int[size + 2];

			inizialize(ranges);

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

	/**
	 * Adds the range.
	 *
	 * @param Value the value
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String Value) throws InvalidRangeException {

		int res[] = convert(Value);

		if (res[1] == -1)
			res[1] = res[0];

		addRange(res[0], res[1]);

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.TotalOrderedSelector#addRange(java.lang.Object)
	 */
	@Override
	public void addRange(Object Value) throws InvalidRangeException {
		if (Value instanceof java.lang.String)
			addRange((String) Value);
		else
			throw new InvalidRangeException();
	}

	/**
	 * Adds the range.
	 *
	 * @param Start the start
	 * @param End the end
	 * @throws InvalidRangeException the invalid range exception
	 */
	public void addRange(String Start, String End) throws InvalidRangeException {
		int start[] = convert(Start);
		int end[] = convert(End);

		addRange(start[0], end[0]);
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.TotalOrderedSelector#addRange(java.lang.Object, java.lang.Object)
	 */
	@Override
	public void addRange(Object Start, Object End) throws InvalidRangeException {
		if (Start instanceof java.lang.String || End instanceof java.lang.String)
			addRange((String) Start, (String) End);
		else
			throw new InvalidRangeException();

	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#complement()
	 */
	public void complement() {
		if (this.isEmpty()) {
			ranges = new int[2];
			ranges[0] = minTime;
			ranges[1] = maxTime;
		} else {
			int size = ranges.length;
			r_copy = new int[size];
			copy();
			if (size > 2 && ranges[size - 1] == -2)
				ranges = new int[size];
			else
				ranges = new int[size + 2];
			inizialize(ranges);
			int index = 0;
			if (r_copy[0] != -2) {
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
					ranges[++index] = maxTime;
					r_copy[i] = maxTime;
					break;
				}
				index++;
			}
			if (r_copy[i] < maxTime) {
				ranges[index] = r_copy[i] + 1;
				ranges[++index] = maxTime;
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
		if (s.isEmpty()) {
			this.empty();
			return;
		} else if (this.isEmpty())
			return;
		else {
			int index = ranges.length + ((TimeSelector) s).ranges.length;
			r_copy = new int[index];
			inizialize(r_copy);
			index = 0;

			int[] external = ((TimeSelector) s).ranges;
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
					int temp_s, temp_e;
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
			}
			int i = 2;
			boolean f = false;
			for (; i < r_copy.length && !f; i++)
				f = r_copy[i] == -2;
			if (f)
				ranges = new int[--i];
			else
				ranges = new int[i];
			inizialize(ranges);
			for (int j = 0; j < i; j++) {
				ranges[j] = r_copy[j];
				ranges[++j] = r_copy[j];
			}
		}
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubsetOrEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubsetOrEquivalent(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;
		if (s.isFull())
			return true;

		int[] si = ((TimeSelector) s).ranges;

		int j = 0, i = 0, size = ranges.length;
		boolean done;

		int st, e;
		while (j < si.length && si[j] != -2) {
			st = si[j];
			e = si[++j];
			done = false;
			while (i < size && !done) {
				if (st <= ranges[i] && e >= ranges[i + 1] && ranges[i] != -2)
					done = true;
				i += 2;
			}
			j++;
			if (!done)
				return false;
		}
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
	@Override
	public boolean isIntersecting(Selector s) throws IllegalArgumentException {
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;
		else if (s.isEmpty())
			return false;

		int[] external = ((TimeSelector) s).ranges;

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

	// @Override
	// public void setMinus(Selector s) throws IllegalArgumentException {
	// if(this.isEmpty() || s.isEmpty())
	// return;
	//
	// TimeSelector s1 = (TimeSelector) s.selectorClone();
	// s1.complement();
	// intersection(s1);
	// }

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isEquivalent(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isEquivalent(Selector s) throws IllegalArgumentException {
		if (this.isEmpty())
			if (s.isEmpty())
				return true;
			else
				return false;
		else if (s.isEmpty())
			return false;
		else if (this.isFull() && s.isFull())
			return true;

		int[] temp = ((TimeSelector) s).ranges;
		int size, t_size;
		size = ranges.length;
		t_size = ranges.length;
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
			return ranges[0] == minTime && ranges[1] == maxTime;
		return false;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#selectorClone()
	 */
	public TimeSelector selectorClone() {
		TimeSelector s = new TimeSelector();
		if (!this.isEmpty()) {
			int size = ranges.length;
			s.ranges = new int[size];
			for (int i = 0; i < size; i++)
				s.ranges[i] = ranges[i];
		}
		return s;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#union(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public void union(Selector s) throws IllegalArgumentException {
		if (!s.isEmpty()) {
			int[] temp = ((TimeSelector) s).ranges;
			int t_size = temp.length;
			for (int i = 0; i < t_size; i++)
				try {
					if (temp[i] == -2)
						return;
					this.addRange(temp[i], temp[++i]);
				} catch (InvalidRangeException e) {
					e.printStackTrace();
				}
		}

	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "full";

		String str = "";
		int size = ranges.length;
		for (int i = 0; i < size; i++) {
			if (ranges[i] == -2 && ranges[i + 1] == -2)
				break;
			str = str + "[" + convert(ranges[i], ranges[++i]) + "] ";
		}
		return str;
	}

	/**
	 * To squid string.
	 *
	 * @return the string
	 */
	public String toSquidString() {

		StringBuffer sb = new StringBuffer();
		int size = ranges.length;
		for (int i = 0; i < size; i++) {
			if (ranges[i] == -2 && ranges[i + 1] == -2)
				break;
			if (i > 0)
				sb.append(" ");
			sb.append(convert(ranges[i], ranges[++i]));
		}
		return sb.toString();
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#toSimpleString()
	 */
	public String toSimpleString() {
		if (this.isEmpty())
			return "empty";
		if (this.isFull())
			return "*";

		StringBuffer sb = new StringBuffer();
		int size = ranges.length;
		for (int i = 0; i < size; i++) {
			if (ranges[i] == -2 && ranges[i + 1] == -2)
				break;
			if (i > 0)
				sb.append(",");
			sb.append(convert(ranges[i], ranges[++i]));
		}
		return sb.toString();
	}

	/**
	 * Gets the max time.
	 *
	 * @return the max time
	 */
	public static int getMaxTime() {
		return maxTime;
	}

	/**
	 * Gets the min time.
	 *
	 * @return the min time
	 */
	public static int getMinTime() {
		return minTime;
	}

	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.selector.Selector#isSubset(eu.fp7.secured.rule.selector.Selector)
	 */
	@Override
	public boolean isSubset(Selector s) throws IllegalArgumentException {
		if (this.isEmpty() || s.isEmpty())
			return false;
		if (s.isFull())
			return true;

		int[] si = ((TimeSelector) s).ranges;

		int j = 0, i = 0, size = ranges.length;
		boolean done, atLeastOne = false;

		int st, e;
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
	 * @see eu.fp7.secured.rule.selector.Selector#length()
	 */
	@Override
	public long length() {
		long sum = 0;
		boolean toggle = true;
		long prev = 0;
		for (int r : ranges) {
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
	 * @see eu.fp7.secured.rule.selector.Selector#full()
	 */
	@Override
	public void full() {
		empty();
		complement();
	}

}
