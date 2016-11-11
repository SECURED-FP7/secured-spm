package dk.brics.automaton;

public class ResolveRegexEquationSystem {

	private static ResolveRegexEquationSystem instance = null;

	private Transition lamdaTransition;

	private ResolveRegexEquationSystem() {
		lamdaTransition = new Transition('@', new State());
	}

	public static ResolveRegexEquationSystem getInstance() {
		if (instance == null)
			return instance = new ResolveRegexEquationSystem();

		return instance;
	}

	public String solve(Automaton a) {

		String[][] matrix;
		Transition t;
		String[] solved;
		int n, m;

		matrix = obtainMatrix(a);

		n = m = a.getNumberOfStates();
		m++;

		solved = new String[n];

		boolean solveAtLeastOne;

		for (State s : a.getAcceptStates())
			solved[s.number] = tryToSolve(matrix[s.number], s.number);

		do {
			solveAtLeastOne = false;

		} while (solveAtLeastOne);
		return "";
	}

	private String tryToSolve(String[] line, int stateNumber) {

		int unKnown[] = new int[line.length];

		String solution[] = line.clone();

		for (int i = 0; i < line.length; i++)
			if (line[i] != null)
				unKnown[i] = 1;

		// String

		return null;
	}

	private String[][] obtainMatrix(Automaton a) {

		String[][] matrix = new String[a.getNumberOfStates()][a.getNumberOfStates() + 1];

		Transition[][] mOrdered = Automaton.getSortedTransitions(a.getStates());

		for (State s : a.getStates()) {
			int lenght = mOrdered[s.number].length;
			int sNumber = s.number;

			for (int i = 0; i < lenght; i++)
				if (mOrdered[sNumber][i].min == mOrdered[sNumber][i].max)
					matrix[sNumber][i] = "" + mOrdered[sNumber][i].min;
				else
					matrix[sNumber][i] = mOrdered[sNumber][i].min + "-" + mOrdered[sNumber][i].min;

			if (s.accept)
				matrix[sNumber][a.getNumberOfStates()] = "";
		}

		printTransitionMatrix(matrix, a.getNumberOfStates());

		return matrix;
	}

	private void printTransitionMatrix(String[][] matrix, int states) {

		if (matrix == null)
			return;

		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < states; i++) {
			sb.append("State ");
			sb.append(i);
			sb.append(": ");
			for (int j = 0; j < matrix[i].length; j++) {
				sb.append('s');
				sb.append(j);
				sb.append('(');

				if (matrix[i][j] != null)
					sb.append(matrix[i][j]);
				else
					sb.append("null");

				sb.append(") - ");

			}
			// sb.append('\x');
			sb.append('\n');
		}

		System.out.println(sb);

	}

}
