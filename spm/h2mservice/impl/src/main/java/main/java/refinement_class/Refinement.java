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



import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.moeaframework.Executor;
import org.moeaframework.core.NondominatedPopulation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.spm.h2mservice.impl.H2mserviceImpl;
import main.java.hspl_class.Mapping;
import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.RefinementType;


public class Refinement {
    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);

	public static void run(String path){
		String schema_file,xml_file;

		schema_file="/refinement/schema/SchemaFile_Schema.xsd";
		xml_file="/refinement/auxiliary_files/input/Schemas.xml";

		Schemas schemas= (Schemas) Useful.unmashal(schema_file, xml_file, Schemas.class);

		String configuration_schema=schemas.getConfigurationSchema();

		Configurations conf=(Configurations) Useful.unmashal(configuration_schema, path, Configurations.class);
		Mapping map = new Mapping();

		Initialization.run(map, conf, schemas);
		PSA_Selection.run(map,conf, schemas);
		Optimization.run(map, conf, schemas);
		SG_Generator.run(map, conf, schemas);
		MSPL_Generator.run(map, conf, schemas);
	}

	public static Configuration run(Configuration conf){

		Initialization.run(conf);
		PSA_Selection.run(conf);
		if(conf.getMap().isIsEnforciability()){
			Optimization.run(conf);
			SG_Generator.run(conf);
			MSPL_Generator.run(conf);
		}

		return conf;

	}

	public static String run(String refinemtType, String hspl_mspl, String sPSA_SG,
            String userPSA, String marketPSA, String subject_string,String content_string,
            String target_string, String optimizationType_string, String maxEvaluationsNo_string){
	    return "";
	}

	// #############################################
	// NEW RUN FUNTION THAT RETUNRS AN Output_Refinement Object
	public static Output_Refinement run2(String refinemtType, String hspl_mspl, String sPSA_SG,
			String userPSA, String marketPSA, String subject_string,String content_string,
			String target_string, String optimizationType_string, String maxEvaluationsNo_string){

// #############################################
/*	    VALUES TO RETURN
	    "application_graph": "<xml>",
	    "MSPL": [
	      "<xml>",
	      "<xml>",
	      "<xml>"
	    ],
	    "remediation": "<xml>"
*/
	    Output_Refinement output_refinement = new Output_Refinement();
// #############################################

	    String output="";

	    try{
	    	//base64
	   
	    		
	    		hspl_mspl=Useful.dencode64(hspl_mspl);
	    		sPSA_SG=Useful.dencode64(sPSA_SG);
	    		userPSA=Useful.dencode64(userPSA);
	    		marketPSA=Useful.dencode64(marketPSA);
	    		subject_string=Useful.dencode64(subject_string);
	    		content_string=Useful.dencode64(content_string);
	    		target_string=Useful.dencode64(target_string);
	    	
	    		
    		Configuration conf=new Configuration (refinemtType, hspl_mspl,sPSA_SG, userPSA, marketPSA, subject_string, content_string,
    				target_string, optimizationType_string, maxEvaluationsNo_string);

    		Initialization.run(conf);
    		LOG.info("\n\nInitialization\n");
    		PSA_Selection.run(conf);
    		LOG.info("\n\n run \n");

    		if(conf.getMap().isIsEnforciability()){
    			Optimization.run(conf);
    			LOG.info("\n\nOptimization\n");
    			SG_Generator.run(conf);
    			LOG.info("\n\nSG_Generator.run\n");
    			MSPL_Generator.run(conf);
    			LOG.info("\n\nMSPL_Generator\n");

    			String ag= conf.mashalSG();
    			//output_refinement.setApplication_grap(ag);
    			output_refinement.setApplication_grap(Useful.encode64(ag));
    			
    			HashSet<String> mspls=conf.mashalMSPLs();
    			
    			//output_refinement.setMspls(mspls);
    			
    				HashSet<String> mspls_64=new HashSet<String>();
    				for(String m: mspls){
    					mspls_64.add(Useful.encode64(m));
        			    output_refinement.setMspls(mspls_64);

    			}
    			
    			output+=ag;
    			for(String s: mspls){
    				output+=s;
    			}

    		}
    		else{
    			output_refinement.setApplication_grap("");
				HashSet<String> mspls_64=new HashSet<String>();
				output_refinement.setMspls(mspls_64);
    			
    			String rem= conf.mashalRemediation();
    			output+=rem;
    			
    			//output_refinement.setRemediation(rem);
    			output_refinement.setRemediation(Useful.encode64(rem));

    				
    		}
	    } catch (Exception e){
	        LOG.error("\n\n*********ERRRORRR *********\n\n");
	        LOG.error(Useful.getStackTrace(e));
	    }

		return output_refinement;

	}


	public static String test(String text){
	    String result = "";
	    LOG.info("\n\n[Refinement] test option " + text);
		try {

			String refinemtType, hspl, mspl, selected_PSA, userPSA, additionalPSA,SG,subject, target,content,optimizationType,maxEvaluationsNo;

			//

			 subject=Useful.readFile("/refinement/auxiliary_files/input/Subject.xml", Charset.defaultCharset());
			 LOG.info("Read file Subject.xml: " + subject);
			 target=Useful.readFile("/refinement/auxiliary_files/input/Target.xml", Charset.defaultCharset());
			 content=Useful.readFile("/refinement/auxiliary_files/input/Content.xml", Charset.defaultCharset());
			 optimizationType="MIN_BUY_COSTMAX_RATING";
			 maxEvaluationsNo="0";



			switch(text){
			case "1":
				refinemtType="POLICY_HSPL";
				hspl = Useful.readFile("/refinement/auxiliary_files/input/HSPL/HSPL_Alice_test.xml", Charset.defaultCharset());
				selected_PSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());

				result = run(refinemtType,hspl,selected_PSA,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);


				break;

			case "2":
				refinemtType="POLICY_MSPL";
				mspl=Useful.readFile("/refinement/auxiliary_files/input/MSPL_List/MSPL.xml", Charset.defaultCharset());
				selected_PSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());


				result = run(refinemtType,mspl,selected_PSA,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);
				break;



			case "3":

				refinemtType="APPLICATION_HSPL";
				hspl = Useful.readFile("/refinement/auxiliary_files/input/HSPL/HSPL_Alice_test.xml", Charset.defaultCharset());
				selected_PSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());

				result = run(refinemtType,hspl,selected_PSA,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);

				break;

			case "4":
				refinemtType="APPLICATION_MSPL";
				mspl=Useful.readFile("/refinement/auxiliary_files/input/MSPL_List/MSPL.xml", Charset.defaultCharset());
				selected_PSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());


				result = run(refinemtType,mspl,selected_PSA,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);
				break;


			case "5":

				refinemtType="APPLICATION_HSPL_SG";
				hspl = Useful.readFile("/refinement/auxiliary_files/input/HSPL/HSPL_Alice_test.xml", Charset.defaultCharset());
				SG=Useful.readFile("/refinement/auxiliary_files/input/SG/SG_Alice1.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());

				result = run(refinemtType,hspl,SG,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);

				break;

			case "6":
				refinemtType="APPLICATION_MSPL_SG";
				mspl=Useful.readFile("/refinement/auxiliary_files/input/MSPL_List/MSPL.xml", Charset.defaultCharset());
				SG=Useful.readFile("/refinement/auxiliary_files/input/SG/SG_Alice1.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());


				result = run(refinemtType,mspl,SG,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);

				break;

			case "7":
				refinemtType="APPLICATION_HSPL";
				hspl = Useful.readFile("/refinement/auxiliary_files/input/HSPL/HSPL_Alice_test.xml", Charset.defaultCharset());
				selected_PSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test_nonEnf.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());

				result = run(refinemtType,hspl,selected_PSA,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);

				break;

			case "8":
				refinemtType="APPLICATION_MSPL_SG";
				mspl=Useful.readFile("/refinement/auxiliary_files/input/MSPL_List/MSPL.xml", Charset.defaultCharset());
				SG=Useful.readFile("/refinement/auxiliary_files/input/SG/SG_Alice3.xml", Charset.defaultCharset());
				userPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());
				additionalPSA=Useful.readFile("/refinement/auxiliary_files/input/PSA/PSA_Alice_test.xml", Charset.defaultCharset());

				result = run(refinemtType,mspl,SG,userPSA,additionalPSA,subject,content,target,optimizationType,maxEvaluationsNo);

				break;


			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return result;

	}
	public static final void main(String[] args) throws MalformedURLException {



			//Refinement.run(args[0]);
		//Configuration conf=new Configuration(args[0]);
		//Refinement.run(conf);


		//test(args[0]);
		test("1");


	}


}






