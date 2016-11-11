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

import java.util.BitSet;

/**
 * The Class Point.
 */
public class Point implements Block{
	
		/** The val. */
		private long val;
		
		/** The bs. */
		private BitSet bs;
		
		/** The start. */
		boolean start;
		
		/** The end. */
		boolean end;

		
		/**
		 * Instantiates a new point.
		 *
		 * @param val the val
		 */
		public Point(long val)
		{
			this.val=val;
			bs = new BitSet();
			this.start = false;
			this.end = false;
		}

		/**
		 * Creates the start point.
		 *
		 * @param val the val
		 * @return the point
		 */
		static Point createStartPoint(long val){	
			Point p =  new Point(val);
			p.start = true;
			return p;
		}
		
		/**
		 * Creates the end point.
		 *
		 * @param val the val
		 * @return the point
		 */
		static Point createEndPoint(long val){
			Point p =  new Point(val);
			p.end = true;
			return p;	
		}
			

		/**
		 * Checks if is start.
		 *
		 * @return true, if is start
		 */
		public boolean isStart()
		{
			return start;
		}

		/**
		 * Checks if is end.
		 *
		 * @return true, if is end
		 */
		public boolean isEnd() {
			return end;
		}

		
		/* (non-Javadoc)
		 * @see eu.fp7.secured.policy.utils.Block#getBs()
		 */
		public BitSet getBs() {
			return bs;
		}
		
		/**
		 * Sets the bs.
		 *
		 * @param bs the new bs
		 */
		public void setBs(BitSet bs) {
			this.bs = bs;
		}
		
		/**
		 * Gets the val.
		 *
		 * @return the val
		 */
		public long getVal() {
			return val;
		}
		
		/* (non-Javadoc)
		 * @see java.lang.Object#toString()
		 */
		
		@Override
		public String toString()
		{
			String s = ""+val+":"+bs;
			return s;
		}
		

		
//		public Point(int val, BitSet bs)
//		{
//			this.val=val;
//			this.bs = bs;
//		}
//		public void setVal(long val) {
//		this.val = val;
//	}
//		public void setStart() {
//			this.start = true;
//			this.end = false;
//		}
//
//
//		public void setEnd() {
//			this.start = false;
//			this.end = true;
//		}



	}
