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
package eu.fp7.secured.policy.translation.semilattice;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.jgraph.graph.DefaultEdge;
import org.jgrapht.DirectedGraph;
import org.jgrapht.alg.ConnectivityInspector;
import org.jgrapht.graph.DefaultDirectedGraph;

import eu.fp7.secured.exception.policy.NotInSemiLatticeException;

/**
 * The Class Semilattice.
 *
 * @param <V> the value type
 */
public class Semilattice<V extends Object> extends
		DefaultDirectedGraph<V, DefaultEdge> implements
		DirectedGraph<V, DefaultEdge> {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 290978073211923528L;
	
	/** The top. */
	V TOP;
	
	/** The root. */
	V ROOT;
	
	/** The ordered. */
	LinkedList<V> ordered;

	/**
	 * Instantiates a new semilattice.
	 *
	 * @param TOP the top
	 * @param ROOT the root
	 */
	public Semilattice(V TOP, V ROOT) {
		super(DefaultEdge.class);
		this.ROOT = ROOT;
		this.TOP = TOP;
	}

	/**
	 * Inits the.
	 */
	public void init() {
		this.addVertex(ROOT);
		this.addVertex(TOP);
		DefaultEdge de = new DefaultEdge();
		de.setSource(ROOT);
		de.setTarget(TOP);
		this.addEdge(ROOT, TOP, de);
	}

	/**
	 * Gets the top.
	 *
	 * @return the top
	 */
	public V getTop() {
		return TOP;
	}

	/**
	 * Gets the root.
	 *
	 * @return the root
	 */
	public V getRoot() {
		return ROOT;
	}

	/**
	 * Adds the vertex between.
	 *
	 * @param to_insert the to_insert
	 * @param before the before
	 * @param after the after
	 * @throws Exception the exception
	 */
	public void addVertexBetween(V to_insert, V before, V after)
			throws Exception {
		// Set vertexSet = this.getVertexSet();
		// if(!vertexSet.contains(before) && !vertexSet.contains(after))

		if (!this.containsVertex(before) && !this.containsVertex(after)) {
			throw new NotInSemiLatticeException();
		}
		// if(vertexSet.contains(to_insert))
		if (this.containsVertex(to_insert)) {
			if (this.getIncomingAdjacentVertices(to_insert).contains(before)
					&& this.getOutgoingAdjacentVertices(to_insert).contains(
							after))
				return;
		}

		DefaultEdge e = this.getEdge(before, after);
		// MoreThanOneTopException not possible
		// the only check is the coverint property
		// System.out.println("ADDVERTEX prima: " + this.getVertexSet() + "\n" +
		// this.getEdgeSet());

		// this.removeListener(listener);
		// AFTER THIS THE LISTENER IS OFF
		// this.add(to_insert);
		this.addVertex(to_insert);
		this.addEdge(before, to_insert);
		this.addEdge(to_insert, after);
		if (e != null) {
			this.removeEdge(e);
		}
		// this.addListener(listener);
		// AFTER THIS THE LISTENER IS ON

		// TODO manage the validate method when addListener/removeListener are
		// called

	}

	/**
	 * Adds the covered vertex.
	 *
	 * @param to_insert the to_insert
	 * @param after the after
	 * @throws Exception the exception
	 */
	public void addCoveredVertex(V to_insert, V after) throws Exception {
		// if(!this.getVertexSet().contains(after))
		if (!this.containsVertex(after)) {
			throw new NotInSemiLatticeException();
		}
		// this.add(to_insert);
		this.addVertex(to_insert);
		this.addEdge(to_insert, after);

	}

	/**
	 * Adds the covering relation.
	 *
	 * @param covered the covered
	 * @param covering the covering
	 * @throws Exception the exception
	 */
	public void addCoveringRelation(V covered, V covering) throws Exception {

		// if(!this.getVertexSet().contains(covered) ||
		// !this.getVertexSet().contains(covering))
		if (!this.containsVertex(covered) || !this.containsVertex(covering)) {
			throw new NotInSemiLatticeException();
		}
		this.addEdge(covered, covering);
	}

	/**
	 * Covering preserving remove.
	 *
	 * @param to_remove the to_remove
	 * @throws Exception the exception
	 */
	public void coveringPreservingRemove(V to_remove) throws Exception {
		// System.out.println("REMOVING VERTEX: " + to_remove );
		if (to_remove.equals(this.getTop())) {
			throw new Exception("Try to remove TOP");
		} else {

			// FROM HERE the SemiLatticeListener is off

			List<V> in_list = this.getIncomingAdjacentVertices(to_remove);
			Iterator<V> in_it = in_list.iterator();
			List<V> out_list = this.getOutgoingAdjacentVertices(to_remove);

			Iterator<V> out_it = out_list.iterator();

			this.removeVertex(to_remove);

			// this.removeEdges(to_remove);
			// Iterator el = this.getEdges(to_remove).iterator();
			// while(el.hasNext())
			// {
			// Edge e = (Edge) el.next();
			// //System.out.println("--->Removing: " + e);
			// this.removeEdge(e);

			// }
			ConnectivityInspector<V, DefaultEdge> inspector = new ConnectivityInspector<V, DefaultEdge>(
					this);
			while (in_it.hasNext()) {
				V v_in = in_it.next();

				while (out_it.hasNext()) {
					V v_out = out_it.next();

					// if(!this.isPath(v_in,v_out))
					if (!inspector.pathExists(v_in, v_out)) {
						this.addEdge(v_in, v_out);
					}
				}
				// System.out.println()
			}
			/*
			 * while(in_it.hasNext()) { Vertex v = (Vertex) in_it.next(); out_it
			 * = out_list.iterator(); while(out_it.hasNext()) { Vertex v2 =
			 * (Vertex) out_it.next(); //if(!this.isConnected(v,v2));
			 * this.addEdge(v,v2);
			 * 
			 * } }
			 */

			// FROM HERE the SemiLatticeListener is on

		}

	}

	/**
	 * Redirect edges.
	 *
	 * @param from the from
	 * @param old_to the old_to
	 * @param new_to the new_to
	 * @throws Exception the exception
	 */
	public void redirectEdges(V from, V old_to, V new_to) throws Exception {
		this.removeEdge(from, old_to);
		this.addEdge(from, new_to);
	}

	/**
	 * Redirect edge from.
	 *
	 * @param old_from the old_from
	 * @param new_from the new_from
	 * @param to the to
	 * @throws Exception the exception
	 */
	public void redirectEdgeFrom(V old_from, V new_from, V to) throws Exception {
		this.removeEdge(old_from, to);
		this.addEdge(new_from, to);
	}

	/**
	 * Removes the cover relation.
	 *
	 * @param covered the covered
	 * @param covering the covering
	 * @throws Exception the exception
	 */
	public void removeCoverRelation(V covered, V covering) throws Exception {
		this.removeEdge(this.getEdge(covered, covering));
	}

	/**
	 * Gets the incoming adjacent vertices.
	 *
	 * @param v the v
	 * @return the incoming adjacent vertices
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 */
	public List<V> getIncomingAdjacentVertices(V v)
			throws NotInSemiLatticeException {
		if (!this.vertexSet().contains(v))
			throw new NotInSemiLatticeException();

		Set<DefaultEdge> edges = this.incomingEdgesOf(v);

		List<V> vertexIn = new LinkedList<V>();

		for (DefaultEdge e : edges) {
			vertexIn.add(this.getEdgeSource(e));
		}

		return vertexIn;
	}

	/**
	 * Gets the outgoing adjacent vertices.
	 *
	 * @param v the v
	 * @return the outgoing adjacent vertices
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 */
	public List<V> getOutgoingAdjacentVertices(V v)
			throws NotInSemiLatticeException {
		if (!this.vertexSet().contains(v))
			throw new NotInSemiLatticeException();

		Set<DefaultEdge> edges = this.outgoingEdgesOf(v);
		List<V> vertexOut = new LinkedList<V>();
		for (DefaultEdge e : edges) {
			vertexOut.add(this.getEdgeTarget(e));
		}

		return vertexOut;
	}
}
