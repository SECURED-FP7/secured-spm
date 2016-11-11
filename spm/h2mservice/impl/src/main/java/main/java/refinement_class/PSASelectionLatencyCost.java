/**********************************************************************************************
 * Copyright (c) 2016 Politecnico di Torino.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *   - POLITO TorSec Team: Fulvio Valenza, Christian Pitscheider, Cataldo Basile, Marco Vallini 
 *	 - SECURED Team 
 *	 - Corresponding: fulvio.valenza@polito.it, cataldo.basile@polito.it
 ************************************************************************************************/
package main.java.refinement_class;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;

import org.moeaframework.core.Solution;
import org.moeaframework.core.variable.BinaryVariable;
import org.moeaframework.problem.AbstractProblem;

public class PSASelectionLatencyCost extends AbstractProblem {
    HashMap hspl_impls; // [0] -> [0, 1] i.e., hspl with id 0 has implementations with ids 0 and 1
                        // [1] -> [2, 3]
    HashMap impls_psa;  // [0] -> [0, 1, 2] i.e., impl with id 0 uses psas with id 0,1,2
    HashMap psaRating; // [0] -> [0.3]
    HashMap psaCost;    // [0] -> [1.0]
    int noVariable = 0;
    int noConstraints = 0;
    String temp;

    public PSASelectionLatencyCost(int noDecisionVariable, int noObjective, HashMap hspl_impls, HashMap impls_psa, HashMap psaRating, HashMap psaCost) {
        super (noDecisionVariable,noObjective);
        this.hspl_impls = hspl_impls;
        this.impls_psa = impls_psa;
        this.psaRating = psaRating;
        this.psaCost = psaCost;
    }

    /*  // model
    // psa1
    psa[0] = 1 impls[0] + 1 impls[1]; // 1 Mb/s
    // psa2
    psa[1] = 1 impls[0];
    // psa3
    psa[2] = 1 impls[1];

    // constraint
    double[] c = new double[3];
    c[0] = 1.1 - impls[0] - impls[1];
    //c[1] = 1 - impls[1];
    //c[2] = 1 - impls[0];


    */

    @Override
    public void evaluate(Solution solution) {

        int[] impls = new int[impls_psa.keySet().size()];
        for(int i=0; i<impls.length; i++){
            BinaryVariable binary = (BinaryVariable) solution.getVariable(i);
            if(binary.get(0)){
                impls[i] = 1;
            } else {
                impls[i] = 0;
            }
        }


        double[] psa = new double[psaRating.keySet().size()]; // N psa

        // constraints
        double[] c = new double[hspl_impls.keySet().size()];

        // for each hspl we need to identify with implementations and psa are involved
        Iterator it = hspl_impls.keySet().iterator();
        while(it.hasNext()){
            String hsplid = (String) it.next();
            LinkedList implsIds = (LinkedList) hspl_impls.get(hsplid);
            // for each impl we need to identify which psa are involved and related constraints
            // constraint
            c[Integer.valueOf(hsplid)] = 1.1;
            Iterator it2 = implsIds.iterator();
            while(it2.hasNext()){
                String implId = (String) it2.next();
                LinkedList psaIds = (LinkedList) impls_psa.get(implId);
                // for each psa we build the equation
                Iterator it3 = psaIds.iterator();
                while(it3.hasNext()){
                    String psaId = (String) it3.next();
                    psa[Integer.valueOf(psaId)] = psa[Integer.valueOf(psaId)] + impls[Integer.valueOf(implId)]; // here we can add the quantity of traffic, e.g., 1Mb introduced by a hspl
                }
                c[Integer.valueOf(hsplid)] = c[Integer.valueOf(hsplid)] - impls[Integer.valueOf(implId)];
            }
        }

        // fobj
        double[] f = new double[1]; // number of objectives
        // fobj1
        // for each psa we derive the latency performance
        it = psaRating.keySet().iterator();
        while(it.hasNext()){
            String psaId = (String) it.next();
            if(psa[Integer.valueOf(psaId)] > 0)
            {
                f[0] = f[0] + (Double.valueOf((String)psaCost.get(psaId))/Double.valueOf((String)psaRating.get(psaId)));
            }
        }

        solution.setObjectives(f);
        solution.setConstraints(c);
    }

    @Override
    public Solution newSolution() {
        noVariable = impls_psa.keySet().size(); // the number of impls
        noConstraints = hspl_impls.keySet().size(); // the number of hspl
        Solution solution = new Solution(noVariable, 1, noConstraints); // 1 objf
        for(int i = 0; i< noVariable; i++){
            solution.setVariable(i, new BinaryVariable(1));
        }

        return solution;
    }


}