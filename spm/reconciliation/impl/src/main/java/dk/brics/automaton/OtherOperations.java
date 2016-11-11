package dk.brics.automaton;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Set;

final public class OtherOperations {

	private OtherOperations() {
	}

	public static boolean equivalent(Automaton a1, Automaton a2) {
		if (a1 == a2)
			return true;

		if (a1.isSingleton()) {
			if (a2.isSingleton())
				return a1.singleton.equals(a2.singleton);
			else
				return false;

		} else if (a2.isSingleton())
			return false;

		// I'm not sure if I need to determize and minimize both automaton
		// a1.determinize();
		// a1.minimize();
		// a2.determinize();
		// a2.minimize();

		if (a1.getStates().size() != a2.getStates().size())
			return false;

		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());

		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashSet<StatePair> visited = new HashSet<StatePair>();
		StatePair p = new StatePair(a1.initial, a2.initial);
		worklist.add(p);
		visited.add(p);
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			if (p.s1.accept && !p.s2.accept)
				return false;
			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];

			if (t1.length != t2.length)
				return false;

			for (int n1 = 0; n1 < t1.length; n1++) {

				int min1 = t1[n1].min, max1 = t1[n1].max;
				int min2 = t2[n1].min, max2 = t2[n1].max;

				if (min1 != min2 || max1 != max2)
					return false;

				StatePair q = new StatePair(t1[n1].to, t2[n1].to);
				if (!visited.contains(q)) {
					worklist.add(q);
					visited.add(q);
				}

			}
		}

		return true;
	}

	public static boolean intersecting(Automaton a1, Automaton a2) {
		if (a1 == a2)
			return true;

		if (a1.isSingleton()) {
			if (a2.isSingleton())
				return a1.singleton.equals(a2.singleton);

			return a2.run(a1.singleton);

		} else if (a2.isSingleton())
			return a1.run(a2.singleton);

		// I'm not sure if I need to determize and minimize both automaton
		a1.determinize();
		// a1.minimize();
		a2.determinize();
		// a2.minimize();

		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());

		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashSet<StatePair> visited = new HashSet<StatePair>();
		StatePair p = new StatePair(a1.initial, a2.initial);
		worklist.add(p);
		visited.add(p);
		// boolean found=false;
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			// if (p.s1.accept && !p.s2.accept)
			// return false;

			if (p.s1.transitions.size() == 0 && !(p.s2.transitions.size() == 0))
				return false;

			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];

			for (int n1 = 0, b2 = 0; n1 < t1.length; n1++) {
				while (b2 < t2.length && t2[b2].max < t1[n1].min)
					b2++;

				if (b2 < t2.length) {
					if (t2[b2].max >= t1[n1].min && t2[b2].min <= t1[n1].max) { // intersecting
																				// condition
						if (t2[b2].to.accept && t1[n1].to.accept)
							// This means that I am in a final state, so
							// I've found a path, between initial state and a
							// final state, that is intersecting
							// so I can say that the automata are intersecting
							// and I don't need to explore
							// the other transition
							return true;
						else {
							StatePair q = new StatePair(t1[n1].to, t2[b2].to);
							if (!visited.contains(q)) {
								worklist.add(q);
								visited.add(q);
							}
						}
					}
					if (t1[n1].max > t2[b2].max)
						// if the t1 char range ends later that t2 char range I
						// need to keep the current t1 range
						// an example t1 range is "d-s" and t2 is "h-l", i need
						// to keep t1 because the next t2
						// could be n-p
						if (b2 != t2.length - 1) {
							n1--;
							b2++;
						}
				}

			}
		}
		return false;
	}

	public static boolean subsetNotEquivalent(Automaton a1, Automaton a2) {

		if (a1.subsetOf(a2))
			return !(OtherOperations.equivalent(a1, a2));
		else
			return false;

		// if (a1 == a2)
		// return false;
		//
		// if (a1.isSingleton()) {
		// if (a2.isSingleton())
		// return false;
		//
		// return a2.run(a1.singleton);
		//
		// } else if (a2.isSingleton())
		// return false;
		//
		//
		// // I'm not sure if I need to determize and minimize both automaton
		// //a1.determinize();
		// //a1.minimize();
		// //a2.determinize();
		// //a2.minimize();
		//
		// Transition[][] transitions1 =
		// Automaton.getSortedTransitions(a1.getStates());
		// Transition[][] transitions2 =
		// Automaton.getSortedTransitions(a2.getStates());
		//
		// LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		// HashSet<StatePair> visited = new HashSet<StatePair>();
		// StatePair p = new StatePair(a1.initial, a2.initial);
		// worklist.add(p);
		// visited.add(p);
		// boolean atLeastOne=false;
		// while (worklist.size() > 0) {
		// p = worklist.removeFirst();
		// if (p.s1.accept && !p.s2.accept)
		// return false;
		//
		// Transition[] t1 = transitions1[p.s1.number];
		// Transition[] t2 = transitions2[p.s2.number];
		// int found=0;
		// for (int n1 = 0, b2 = 0; n1 < t1.length; n1++) {
		// while (b2 < t2.length && t2[b2].max < t1[n1].min)
		// b2++;
		//
		// if (b2<t2.length){
		// if (t2[b2].max >= t1[n1].max && t2[b2].min <= t1[n1].min){
		// //subset/Equivalent condition
		// if (t2[b2].max != t1[n1].max || t2[b2].min != t1[n1].min) //check for
		// subset
		// atLeastOne=true;
		// found ++;
		// StatePair q = new StatePair(t1[n1].to, t2[b2].to);
		// if (!visited.contains(q)) {
		// worklist.add(q);
		// visited.add(q);
		// }
		//
		// }
		// if (t1[n1].max > t2[b2].max)
		// //if the t1 char range ends later that t2 char range I need to keep
		// the current t1 range
		// //an example t1 range is "d-s" and t2 is "h-l", i need to keep t1
		// because the next t2
		// //could be n-p
		// if (b2!=t2.length-1){
		// n1--;
		// b2++;
		// }
		// }
		//
		// }
		// if (found<t1.length)
		// return false;
		// }
		// if (!atLeastOne)
		// if (a1.getNumberOfStates()<a2.getNumberOfStates())
		// return true;
		//
		// return atLeastOne;
	}

	public static String toRegExp(Automaton automa) {

		if (automa.isEmpty() || automa.isEmptyString())
			return "";

		Automaton a = automa.clone();

		if (a.isSingleton()) {
			return a.singleton;
		}

		char character = (char) Character.MIN_VALUE + 1;

		a.determinize();
		// a.minimize();

		// System.out.println(a);

		int fsCount = 0;
		Set<State> finalStateSet = new HashSet<State>();

		// //boolean endsWith =false;

		// Check if the final (accept) state of the automata is .*
		// if true clone the automaton, remove the final transition and
		// tries to determines if the endsWith condition holds (this mean that
		// the regex is .*(blabla).*
		boolean finalStateAny = false;
		Set<State> acceptstates = a.getAcceptStates();
		if (acceptstates.size() == 1) {
			Set<Transition> ts = acceptstates.iterator().next().transitions;
			if (ts != null)
				if (ts.size() == 1) {
					// the final state of the automata must have only one
					// transition and
					// the transition must be directed to the state itself. The
					// range of
					// char od this transition must be \u0000-\uffff
					// if these characteristic are not respetcted the iphothesis
					// does not
					// hold
					Transition t = ts.iterator().next();
					if (t.to.equals(acceptstates.iterator().next()))
						if (t.min == Character.MIN_VALUE && t.max == Character.MAX_VALUE)
							finalStateAny = true;
				}

		}

		Automaton a1 = null;
		if (finalStateAny) {
			// System.out.println("FINAL STATE ANY");
			a1 = a.clone();
			State acS = a.getAcceptStates().iterator().next();
			acS.transitions.clear();
			for (State s : a.getStates()) {
				if (!s.equals(acS))
					acS.transitions.add(new Transition('k', s));
			}
			a.determinize();

		}

		boolean endsWith = checkForEndWith(a);

		// System.out.println("EndsWith: "+endsWith);
		// System.out.println("+++++++++++++++++++++++++");

		if (finalStateAny)
			if (!endsWith)
				a = a1;
			else
				a.getAcceptStates().iterator().next().transitions.clear();

		for (State s : a.getStates())
			if (s.accept && (s.getTransitions().isEmpty() || hasOnlyAutoT(s))) {
				finalStateSet.add(s);
				fsCount++;
				// System.out.println("Final State: "+s);
			}

		// System.out.println("=====================");
		// System.out.println(a);
		// System.out.println("=====================");

		State finalState = null;

		if (fsCount > 1) {
			finalState = new State();
			for (State s : finalStateSet) {
				Transition tr = new Transition(character++, finalState);
				tr.temp = "";
				s.addTransition(tr);
			}
			// System.out.println("********DENTRO***********");
			// System.out.println(a);
			// System.out.println("********DENTRO***********");
		} else {
			try {
				finalState = finalStateSet.iterator().next();
			} catch (NoSuchElementException e) {
				System.err.println("automata2regex error, some transformation is generating errors.");
			}
		}

		State initialState = a.getInitialState();

		/*
		 * Transition[][] tttt = a.getSortedTransitions(a.getStates());
		 * 
		 * for(int i=0;i<tttt.length;i++) for(Transition t : tttt[i])
		 * System.out.println(t);
		 * 
		 * if (t.min==Character.MIN_VALUE && st.max==Character.MAX_VALUE)
		 * if(st.min!=st.max) toAdd=toAdd+"[^"+(t.max+1)+"-"+(st.min-1)+"]";
		 * else toAdd=toAdd+"^"+(t.min+1); else
		 */
		// Ricerca di ^
		for (State s : a.getStates()) {
			LinkedList<Transition> transitions = new LinkedList<Transition>(s.transitions);
			Set<State> alreadyDoneStates = new HashSet<State>();

			for (int i = 0; i < transitions.size(); i++) {
				LinkedList<Transition> ordTransitions = new LinkedList<Transition>();
				Transition t1 = transitions.get(i);

				if (!alreadyDoneStates.contains(t1.to)) {
					ordTransitions.add(0, t1);

					for (int j = i + 1; j < transitions.size(); j++) {
						Transition t2 = transitions.get(j);
						if (t1.to == t2.to) {
							boolean added = false;
							for (int k = 0; k < ordTransitions.size() && !added; k++) {
								Transition t3 = ordTransitions.get(k);
								if (t2.min < t3.min) {
									ordTransitions.add(k, t2);
									added = true;
								}
							}
							if (!added)
								ordTransitions.addLast(t2);
						}
					}

					if (ordTransitions.get(0).min == Character.MIN_VALUE)
						if (ordTransitions.size() > 1) {
							String temp = "[^";
							for (Transition t4 : ordTransitions) {
								if (t4.min != t4.max) {
									if (t4.min != Character.MIN_VALUE)
										temp = temp + "-" + (char) (t4.min - 1);
									if (t4.max != Character.MAX_VALUE)
										temp = temp + (char) (t4.max + 1);

									s.transitions.remove(t4);
								}

							}
							temp = temp + "]";
							Transition newT = new Transition(character++, t1.to);
							newT.temp = temp;
							s.transitions.add(newT);
							alreadyDoneStates.add(t1.to);
						}
				}

			}

		}

		int totalState = a.getStates().size();
		// int processedState=0;

		while (!checkDone(initialState, finalState)) {
			LinkedList<State> states = new LinkedList<State>(a.getStates());

			LinkedList<Transition> transitions = new LinkedList<Transition>(initialState.transitions);

			// Set<State> processed = new HashSet<State>();

			for (Transition t : transitions) {
				State s = t.to;
				if (s != finalState) {
					initialState.transitions.remove(t);

					String temp = "";

					if (t.temp == null)
						if (t.min != t.max) {
							if (t.min == Character.MIN_VALUE && t.max == Character.MAX_VALUE)
								temp = ".";
							else
								temp = "[" + t.min + "-" + t.max + "]";
						} else
							temp = "" + t.min;
					else
						temp = t.temp;

					String auto = "";

					int count = 0;

					for (Transition st : s.transitions) {
						if (st.to == s) {
							if (st.min != st.max)
								if (st.min == Character.MIN_VALUE && st.max == Character.MAX_VALUE)
									auto = auto + ".|";
								else
									auto = auto + "[" + st.min + "-" + st.max + "]|";
							else
								auto = auto + st.min + '|';

							count++;
						}
					}

					if (count > 0) {
						auto = auto.substring(0, auto.length() - 1);
						if (count > 1)
							auto = "(" + auto + ")";
						auto = auto + "*";
						temp = temp + auto;
					}

					String toAdd = "";
					Set<Transition> tClone = new HashSet<Transition>(s.transitions);

					for (Transition st : tClone) {
						if (st.to != s) {
							if (st.temp == null)
								if (st.min != st.max)
									if (st.min == Character.MIN_VALUE && st.max == Character.MAX_VALUE)
										toAdd = toAdd + ".";
									else
										toAdd = toAdd + "[" + st.min + "-" + st.max + "]";
								else
									toAdd = toAdd + st.min;
							else
								toAdd = st.temp;
							Transition nt = new Transition(character++, st.to);
							nt.temp = temp + toAdd;
							initialState.transitions.add(nt);
							toAdd = "";
						}
					}

					/*
					 * if (!processed.contains(s)){ processedState++;
					 * processed.add(s); }
					 */

				}

			}
		}

		String regularExpression = "";
		if (totalState > 1) {
			for (Transition t : initialState.transitions) {
				if (t.temp != null)
					regularExpression = regularExpression + t.temp + "|";
				else {
					if (t.min != t.max)
						if (t.min == Character.MIN_VALUE && t.max == Character.MAX_VALUE)
							regularExpression = regularExpression + ".|";
						else
							regularExpression = regularExpression + "[" + t.min + "-" + t.max + "]|";
					else
						regularExpression = regularExpression + t.min + '|';
				}
			}
			regularExpression = regularExpression.substring(0, regularExpression.length() - 1);
		}

		int count = 0;
		String auto = "";
		if (finalState != null) {
			for (Transition t : finalState.transitions) {
				if (t.temp == null)
					if (t.min != t.max)
						if (t.min == Character.MIN_VALUE && t.max == Character.MAX_VALUE)
							auto = auto + ".|";
						else
							auto = auto + "[" + t.min + "-" + t.max + "]|";
					else
						auto = auto + t.min + '|';
				else
					auto = t.temp;

				count++;
			}
		}
		
		if (count > 0) {
			auto = auto.substring(0, auto.length() - 1);
			if (count > 1)
				auto = "(" + auto + ")";
			auto = auto + "*";
			regularExpression = regularExpression + auto;
		}

		if (endsWith) {
			regularExpression = ".*" + regularExpression;
			if (finalStateAny)
				regularExpression = regularExpression + ".*";
		}

		return postParsing(regularExpression);

	}

	private static boolean checkDone(State initial, State finalState) {
		for (Transition t : initial.transitions)
			if (t.to != finalState)
				return false;
		return true;
	}

	private static String postParsing(String regexp) {
		if (regexp.endsWith(".*") && regexp.startsWith(".*"))
			return regexp;
		if (regexp.endsWith(".*"))
			return "^" + regexp.substring(0, regexp.length() - 2);
		if (regexp.startsWith(".*"))
			return regexp.substring(2, regexp.length()) + "$";
		return regexp;
	}

	private static boolean hasOnlyAutoT(State s) {

		for (Transition t : s.transitions)
			if (t.to != s)
				return false;

		return true;

	}

	private static boolean checkForEndWith(Automaton a) {

		Set<State> states = a.getStates();

		// boolean foundIn=false;
		// for (State s : states)
		// if (s.equals(a.getInitialState())){
		// System.out.println("Contains initial equals");
		// foundIn=true;
		// }
		// else if (s.compareTo(a.initial)==0) {
		// System.out.println("Contains initial compare");
		// foundIn=true;
		// }
		//
		// if (!foundIn)
		// states.add(a.initial);

		for (State s : states) {
			boolean found = false;
			for (Transition t : s.transitions) {
				if (t.to.equals(a.getInitialState()))
					found = true;
			}

			if (!found) {
				// System.out.println("NOT FOUND: "+s);
				return false;
			}
		}

		// System.out.println("Sono qua quindi ho trovato trans to initial in ogni stato. Rimuovo");

		HashMap<State, LinkedList<State>> initialList = new HashMap<State, LinkedList<State>>();
		for (State s : states)
			initialList.put(s, new LinkedList<State>());

		for (State s : states) {
			Set<Transition> toRemove = new HashSet<Transition>();
			for (Transition t : s.transitions) {

				if (t.to.equals(a.initial))
					toRemove.add(t);
				else
					initialList.get(t.to).add(s);
			}

			s.transitions.removeAll(toRemove);

		}

		int stateNumber = states.size();

		State startRegex = null;

		// System.out.println("SONO QUA");
		// System.out.println(a);
		for (State s : initialList.keySet()) {
			if (initialList.get(s).size() >= stateNumber) {
				boolean foundInitial = true;
				for (State s1 : states) {
					if (!initialList.get(s).contains(s1))
						foundInitial = false;
				}
				if (foundInitial)
					if (startRegex == null) {
						startRegex = s;
						// System.out.println("//////////////////");
						// System.out.println(startRegex);
						// System.out.println("//////////////////");
					}
				// else
				// System.out.println("CI SONO 2 stati che sono raggiungibili da tutti gli altri stati. Problema.");

			}

		}
		// System.out.println("SONO SOTTO QUA");

		// if (startRegex==null)
		// System.out.println("\tNULL");
		// else System.out.println("startregex : "+startRegex);

		if (startRegex != null) {
			for (State s : states)
				if (!s.equals(a.initial)) {
					Set<Transition> toRemove = new HashSet<Transition>();
					for (Transition t : s.transitions)
						if (t.to.equals(startRegex))
							toRemove.add(t);

					s.transitions.removeAll(toRemove);

				}

		} else {
			// System.out.println("Non ho trovato startregex");
			char starter = a.initial.transitions.iterator().next().min;

			char todelete[] = new char[a.getStates().size()];

			State current = a.initial.transitions.iterator().next().to;
			Set<State> visited = new HashSet<State>();

			while (current != null) {
				Set<Transition> toremove = new HashSet<Transition>();
				if (current.transitions != null) {
					for (Transition t : current.transitions) {
						if (t.min == starter) {
							if (t.to.equals(current) || visited.contains(t.to))
								toremove.add(t);

						} else if (visited.contains(t.to))
							toremove.add(t);

					}
					visited.add(current);
					current.transitions.removeAll(toremove);
					// TODO lista di next

				}

				if (current.accept)
					current = null;
				else if (current.transitions != null)
					current = current.transitions.iterator().next().to;
			}

		}

		System.out.println("QUESTO è l'automa dentro check:\n" + a);
		return true;
	}
}
