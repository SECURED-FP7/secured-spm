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

import java.util.HashSet;

public class Output_Refinement {

    private String  application_grap;
    private HashSet<String> mspls;
    private String remediation;


    public String getApplication_grap() {
     return application_grap;
    }
    public void setApplication_grap(String application_grap) {
     this.application_grap = application_grap;
    }
    public HashSet<String> getMspls() {
     return mspls;
    }
    public void setMspls(HashSet<String> mspls) {
     this.mspls = mspls;
    }
    public String getRemediation() {
     return remediation;
    }
    public void setRemediation(String remediation) {
     this.remediation = remediation;
    }

   }