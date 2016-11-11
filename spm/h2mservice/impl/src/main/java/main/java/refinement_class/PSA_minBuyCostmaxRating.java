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


import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.moeaframework.Analyzer;
import org.moeaframework.Executor;
import org.moeaframework.core.NondominatedPopulation;
import org.moeaframework.core.Solution;
import org.moeaframework.core.variable.BinaryVariable;
import org.moeaframework.problem.AbstractProblem;
import org.moeaframework.util.progress.ProgressListener;

//import main.java.refinement_class.PSA_minTransferCostminLatency.PSASelectionLatencyCost;

public class PSA_minBuyCostmaxRating {

        HashMap hspl_impls_ext = new HashMap();
        HashMap impls_psa_ext = new HashMap();
        HashMap psa_rating_ext = new HashMap();
        HashMap psa_cost_ext = new HashMap();


        // internal representation
        HashMap hspl_impls = new HashMap();
        HashMap impls_psa = new HashMap();
        HashMap psa_latency = new HashMap();
        HashMap psa_cost = new HashMap();

        // external vs internal mapping
        HashMap hspl_index = new HashMap();
        HashMap impls_index = new HashMap();
        HashMap psa_index = new HashMap();
        int hspl_i = 0;
        int impl_i = 0;
        int psa_i = 0;

        int noVariable;

        // optimization results
        NondominatedPopulation optResult = null;

        public void loadExternalRepresentation(HashMap hspl_impls_ext_input, HashMap impls_psa_ext_input, HashMap psa_rating_ext_input, HashMap psa_cost_ext_input ){
            hspl_impls_ext=hspl_impls_ext_input;
            impls_psa_ext=impls_psa_ext_input;
            psa_rating_ext=psa_rating_ext_input;
            psa_cost_ext=psa_cost_ext_input;
        }



        public void loadExternalRepresentationFromFile(String filename){
            // read JSON file
            try {
                // read the json file
                FileReader reader = new FileReader(filename);

                JSONParser jsonParser = new JSONParser();
                JSONObject jsonObject = (JSONObject) jsonParser.parse(reader);

                // reading hspl_impls
                JSONArray hsplImpls = (JSONArray) jsonObject.get("hspl_impls");

                Iterator it = hsplImpls.iterator();
                while(it.hasNext()){
                    JSONObject innerObj = (JSONObject) it.next();
                    JSONObject hspl = (JSONObject) innerObj.get("hspl");
                    String hsplid = (String) hspl.get("hsplid");
                    JSONArray impls = (JSONArray) innerObj.get("impls");
                    LinkedList l = new LinkedList();
                    Iterator it1 = impls.iterator();
                    while(it1.hasNext()){
                        JSONObject impl = (JSONObject) it1.next();
                        String implid = (String) impl.get("implid");
                        l.add(implid);
                    }
                    hspl_impls_ext.put(hsplid, l);
                }

                // reading impl_psas
                JSONArray implPsas = (JSONArray) jsonObject.get("impl_psa");

                it = implPsas.iterator();
                while(it.hasNext()){
                    JSONObject innerObj = (JSONObject) it.next();
                    JSONObject impl = (JSONObject) innerObj.get("impl");
                    String implid = (String) impl.get("implid");
                    JSONArray psas = (JSONArray) innerObj.get("psas");
                    LinkedList l = new LinkedList();
                    Iterator it1 = psas.iterator();
                    while(it1.hasNext()){
                        JSONObject psa = (JSONObject) it1.next();
                        String psaid = (String) psa.get("psaid");
                        l.add(psaid);
                    }
                    impls_psa_ext.put(implid, l);
                }

                // reading psa latency
                JSONArray psaRating = (JSONArray) jsonObject.get("psa_rating");
                it = psaRating.iterator();
                while(it.hasNext()){
                    JSONObject innerObj = (JSONObject) it.next();
                    String id = (String) innerObj.get("id");
                    String latency = (String) innerObj.get("rating");
                    psa_rating_ext.put(id, latency);
                }

                // reading psa cost
                JSONArray psaCost = (JSONArray) jsonObject.get("psa_cost");
                it = psaCost.iterator();
                while(it.hasNext()){
                    JSONObject innerObj = (JSONObject) it.next();
                    String id = (String) innerObj.get("id");
                    String cost = (String) innerObj.get("cost");
                    psa_cost_ext.put(id, cost);
                }


            } catch (FileNotFoundException ex) {
                ex.printStackTrace();
            } catch (IOException ex) {
                ex.printStackTrace();
            } catch (ParseException ex) {
                ex.printStackTrace();
            } catch (NullPointerException ex) {
                ex.printStackTrace();
            }

            noVariable = impls_psa_ext.keySet().size(); // the number of impls
        }

        public void transformExternalToInternalRepresentation(){
            // transforming hspl_impls
            Iterator it = hspl_impls_ext.keySet().iterator();
            while(it.hasNext()){
                String hsplid_ext = (String) it.next();
                String hsplid_int = this.generateInternalhsplId(hsplid_ext);
                LinkedList l_ext = (LinkedList) this.hspl_impls_ext.get(hsplid_ext);
                LinkedList l_int = new LinkedList();
                Iterator it1 = l_ext.iterator();
                while(it1.hasNext()){
                    String implid_ext = (String) it1.next();
                    String implid_int = this.generateInternalimplId(implid_ext);
                    l_int.add(implid_int);
                }
                this.hspl_impls.put(hsplid_int, l_int);
            }

            // transforming impls_psa
            it = impls_psa_ext.keySet().iterator();
            while(it.hasNext()){
                String implid_ext = (String) it.next();
                String implid_int = this.generateInternalimplId(implid_ext);
                LinkedList l_ext = (LinkedList) this.impls_psa_ext.get(implid_ext);
                LinkedList l_int = new LinkedList();
                Iterator it1 = l_ext.iterator();
                while(it1.hasNext()){
                    String psaid_ext = (String) it1.next();
                    String psaid_int = this.generateInternalpsaId(psaid_ext);
                    l_int.add(psaid_int);
                }
                this.impls_psa.put(implid_int, l_int);
            }

            // transforming psa_latency
            it = psa_rating_ext.keySet().iterator();
            while(it.hasNext()){
                String psaid_ext = (String) it.next();
                String psaid_int = this.generateInternalpsaId(psaid_ext);
                String latency = (String) this.psa_rating_ext.get(psaid_ext);
                this.psa_latency.put(psaid_int, latency);
            }

            // transforming psa_cost
            it = psa_cost_ext.keySet().iterator();
            while(it.hasNext()){
                String psaid_ext = (String) it.next();
                String psaid_int = this.generateInternalpsaId(psaid_ext);
                String cost = (String) this.psa_cost_ext.get(psaid_ext);
                this.psa_cost.put(psaid_int, cost);
            }

        }

        public String generateInternalhsplId(String hsplid_ext){
            String result = "";

            if(!this.hspl_index.containsKey(hsplid_ext)){
                result = String.valueOf(this.hspl_i);
                this.hspl_index.put(hsplid_ext, result);
                this.hspl_i++;
            } else {
                result = (String) this.hspl_index.get(hsplid_ext);
            }

            return result;
        }

        public String generateInternalimplId(String implid_ext){
            String result = "";

            if(!this.impls_index.containsKey(implid_ext)){
                result = String.valueOf(this.impl_i);
                this.impls_index.put(implid_ext, result);
                this.impl_i++;
            } else {
                result = (String) this.impls_index.get(implid_ext);
            }

            return result;
        }

        public String generateInternalpsaId(String psaid_ext){
            String result = "";

            if(!this.psa_index.containsKey(psaid_ext)){
                result = String.valueOf(this.psa_i);
                this.psa_index.put(psaid_ext, result);
                this.psa_i++;
            } else {
                result = (String) this.psa_index.get(psaid_ext);
            }

            return result;
        }

        public void optimize(int maxEvalutationsNo){
            System.out.println();
            System.out.println("Optimization results:");
            Thread.currentThread().setContextClassLoader(PSASelectionLatencyCost.class.getClassLoader());
            Thread.currentThread().setContextClassLoader(PSA_minBuyCostmaxRating.class.getClassLoader());
            Thread.currentThread().setContextClassLoader(Executor.class.getClassLoader());
            NondominatedPopulation result = new Executor()
                    .withProblem("UF1")
                    .withAlgorithm("NSGAII")
                    .withMaxEvaluations(10000)
                    .distributeOnAllCores()
                    .run();

            System.out.println("Testing:" + result.toString());

            if(maxEvalutationsNo < 1000){
                optResult = new Executor()
                        .withProblemClass(PSASelectionLatencyCost.class,noVariable,2, hspl_impls, impls_psa, psa_latency, psa_cost)
                        .withAlgorithm("NSGAII")
                        .run();
            } else {
                optResult = new Executor()
                        .withProblemClass(PSASelectionLatencyCost.class,noVariable,2, hspl_impls, impls_psa, psa_latency, psa_cost)
                        .withAlgorithm("NSGAII")
                        .withMaxEvaluations(maxEvalutationsNo)
                        .run();
            }

        }

        public void printProblem(){
            // print hspl and implementations
            System.out.println("HSPL and Implementations:");
            Iterator it = hspl_impls_ext.keySet().iterator();
            while(it.hasNext()){
                String hsplId = (String) it.next();
                System.out.print("hspl "+ hsplId + " has implementations: ");
                LinkedList impls = (LinkedList) hspl_impls_ext.get(hsplId);
                Iterator it1 = impls.iterator();
                while(it1.hasNext()){
                    String implid = (String) it1.next();
                    System.out.print(implid + " ");
                }
                System.out.println();
            }
            // print implementations and psa
            System.out.println();
            System.out.println("Implementations and PSA:");
            it = impls_psa_ext.keySet().iterator();
            while(it.hasNext()){
                String implId = (String) it.next();
                System.out.print(implId + " has PSA: ");
                LinkedList psas = (LinkedList) impls_psa_ext.get(implId);
                Iterator it1 = psas.iterator();
                while(it1.hasNext()){
                    String psaid = (String) it1.next();
                    System.out.print(psaid + " ");
                }
                System.out.println();
            }
            // print psa latency
            System.out.println();
            System.out.println("PSA rating:");
            it = psa_rating_ext.keySet().iterator();
            while(it.hasNext())
            {
                String psaid = (String) it.next();
                System.out.println(psaid + " has rating " + psa_rating_ext.get(psaid));
            }
            // print psa cost
            System.out.println();
            System.out.println("PSA cost:");
            it = psa_cost_ext.keySet().iterator();
            while(it.hasNext())
            {
                String psaid = (String) it.next();
                System.out.println(psaid + " has cost " + psa_cost_ext.get(psaid));
            }
        }

        public void printSolution(){
            //display the results

            for(int i=0; i < this.getSolutionNumber(); i++)
            {
                HashMap sol = this.getSolution(i);
                System.out.println("Solution " + (i+1));
                System.out.println("Cost/Rating:" + sol.get("cost_rating"));
                HashMap implResult = this.getSolutionVariables(i);
                Iterator it = hspl_impls_ext.keySet().iterator();
                while(it.hasNext()){
                    String hsplid = (String) it.next();
                    System.out.println("hspl " + hsplid + " available implementations and results: ");
                    LinkedList impls = (LinkedList) hspl_impls_ext.get(hsplid);
                    Iterator it1 = impls.iterator();
                    while(it1.hasNext()){
                        String implId = (String) it1.next();
                        System.out.println(implId + " value (1 when selected): " + implResult.get(implId));
                    }
                }
            }

        }

        public int getSolutionNumber(){
            return optResult.size();
        }

        public HashMap getSolution(int number){
            HashMap result = new HashMap();
            Solution s = optResult.get(number);
            result.put("cost_rating", s.getObjective(0));

            return result;
        }

        public HashMap getSolutionVariables(int solNumber){
            HashMap result = new HashMap();
            Solution s = optResult.get(solNumber);
            Iterator it = impls_index.keySet().iterator();
            while(it.hasNext()){
                String implid_ext = (String) it.next();
                String implid_int = (String) impls_index.get(implid_ext);
                int value = Integer.valueOf(s.getVariable(Integer.valueOf(implid_int)).toString());
                result.put(implid_ext, value);
            }

            return result;
        }
    }

    /**
     * @param args
     */
/*    public static void main(String[] args) {

        OptWrapper w = new OptWrapper();
        w.loadExternalRepresentationFromFile("/refinement/java/input/test_minBuyCost_maxRating.json");
        w.transformExternalToInternalRepresentation();
        w.printProblem();
        w.optimize(0);
        w.printSolution();

    }*/


//}
