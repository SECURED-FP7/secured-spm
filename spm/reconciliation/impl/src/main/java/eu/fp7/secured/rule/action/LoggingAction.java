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
package eu.fp7.secured.rule.action;

import java.math.BigInteger;

/**
 * The Enum LoggingAction.
 */
public class LoggingAction implements Action {
	
	private String event;
	private int interval;
	private int threshold;
	
	
	public LoggingAction(String event, int interval, int threshold){
		this.event = event;
		this.interval = interval;
		this.threshold = threshold;
	}
	

	public String getEvent() {
		return event;
	}

	public int getInterval() {
		return interval;
	}

	public int getThreshold() {
		return threshold;
	}

	/*
	 * (non-Javadoc)
	 * @see java.lang.Enum#toString()
	 */
	public String toString(){
		return "LOGGING "+event+"("+interval+", "+threshold+")";
	}
	
	/* (non-Javadoc)
	 * @see eu.fp7.secured.rule.action.Action#actionClone()
	 */
	@Override
	public Action actionClone() {
		return new LoggingAction(event, interval, threshold);
	}
}
