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

public class Semilattice<V extends Object> extends
		DefaultDirectedGraph<V, DefaultEdge> implements
		DirectedGraph<V, DefaultEdge> {

	/**
	 * 
	 */
	private static final long serialVersionUID = 290978073211923528L;
	V TOP;
	V ROOT;
	LinkedList<V> ordered;

	public Semilattice(V TOP, V ROOT) {
		super(DefaultEdge.class);
		this.ROOT = ROOT;
		this.TOP = TOP;
	}

	public void init() {
		this.addVertex(ROOT);
		this.addVertex(TOP);
		DefaultEdge de = new DefaultEdge();
		de.setSource(ROOT);
		de.setTarget(TOP);
		this.addEdge(ROOT, TOP, de);
	}

	public V getTop() {
		return TOP;
	}

	public V getRoot() {
		return ROOT;
	}

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

	public void addCoveredVertex(V to_insert, V after) throws Exception {
		// if(!this.getVertexSet().contains(after))
		if (!this.containsVertex(after)) {
			throw new NotInSemiLatticeException();
		}
		// this.add(to_insert);
		this.addVertex(to_insert);
		this.addEdge(to_insert, after);

	}

	public void addCoveringRelation(V covered, V covering) throws Exception {

		// if(!this.getVertexSet().contains(covered) ||
		// !this.getVertexSet().contains(covering))
		if (!this.containsVertex(covered) || !this.containsVertex(covering)) {
			throw new NotInSemiLatticeException();
		}
		this.addEdge(covered, covering);
	}

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

	public void redirectEdges(V from, V old_to, V new_to) throws Exception {
		this.removeEdge(from, old_to);
		this.addEdge(from, new_to);
	}

	public void redirectEdgeFrom(V old_from, V new_from, V to) throws Exception {
		this.removeEdge(old_from, to);
		this.addEdge(new_from, to);
	}

	/**
	 * 
	 * @throws Exception
	 */
	public void removeCoverRelation(V covered, V covering) throws Exception {
		this.removeEdge(this.getEdge(covered, covering));
	}

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
