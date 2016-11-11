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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;

import org.jfree.util.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.tools.xjc.reader.Util;

import eu.fp7.secured.spm.h2mservice.impl.H2mserviceImpl;
import main.java.schemaFile_class.Schemas;
import main.java.associationList_class.Association;
import main.java.associationList_class.AssociationList;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.OptimizationType;
import main.java.configuration_class.RefinementType;
import main.java.matching_class.Matching;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.hspl_class.Candidates;
import main.java.hspl_class.CapabilityList;
import main.java.hspl_class.Hspl;
import main.java.hspl_class.MSPL;
import main.java.hspl_class.Mapping;
import main.java.hspl_class.SuitableImplementationList;

public class Configuration {
    private Mapping map;
    private RefinementType refinementType;
    private HashSet<ITResource> mspl_list;

    private AssociationList subject;
    private AssociationList content;
    private AssociationList target;
    private int maxEvaluationsNo;
    private OptimizationType optimizationType;
    private Matching matching;


    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);

    public Configuration (String refinemtType, String hspl_mspl, String sPSA_SG,
            String userPSA, String additionalPSA, String subject_string,
            String content_string, String target_string, String optimizationType_string, String maxEvaluationsNo_string){

        map=new Mapping();
        mspl_list=new HashSet<ITResource>();
        Path path;
        File temp;

        refinementType= RefinementType.valueOf(refinemtType);

        if(refinementType.equals(RefinementType.POLICY_HSPL)||
                refinementType.equals(RefinementType.APPLICATION_HSPL) ||
                refinementType.equals(RefinementType.APPLICATION_HSPL_SG) ){

            //setHSPL(conf.getHsplFile());

            //--
            //String path_hspl = "/refinement/auxiliary_files/input/HSPL/HSPL.xml";

            //++
            try {
                temp = File.createTempFile("HSPL", ".xml");
                String path_hspl = temp.getPath();
                path = Paths.get(path_hspl);

                if (Files.exists(path)) {
                    // file exist
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

                try {

                    Files.write( Paths.get(path_hspl), hspl_mspl.getBytes(), StandardOpenOption.CREATE);
                    setHSPL(path_hspl);

                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
                LOG.error(Useful.getStackTrace(e1));
            }
        }

        if( refinementType.equals(RefinementType.POLICY_MSPL)||
                refinementType.equals(RefinementType.APPLICATION_MSPL)||
                refinementType.equals(RefinementType.APPLICATION_MSPL_SG)){

            try {

                Pattern p = Pattern.compile("\\<\\?xml");
                String [] mspl_string=hspl_mspl.split(p.pattern());
                int i=0;
                String path_mspl;
                for(String s: mspl_string ){
                    if(!s.equals("")){
                        s="<?xml"+s;

                        //--
                        //path_mspl= "/refinement/auxiliary_files/input/MSPL_List/MSPL"+i+".xml";
                        //++
                        temp = File.createTempFile("MSPL"+i, ".xml");
                        path_mspl = temp.getPath();

                        //path_mspl= "/tmp/MSPL"+i+".xml";
                        path = Paths.get(path_mspl);

                        if (Files.exists(path)) {
                            // file exist
                            try {
                                Files.delete(path);
                            } catch (IOException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                        }

                        Files.write( Paths.get(path_mspl), s.getBytes(), StandardOpenOption.CREATE);
                        addMSPL(path_mspl);
                        i++;

                    }
                }


            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }

        if(! refinementType.equals(RefinementType.APPLICATION_HSPL_SG) &&  !refinementType.equals(RefinementType.APPLICATION_MSPL_SG) ){
            //--
            //String path_selectePSA = "/refinement/auxiliary_files/input/PSA/selected_PSA.xml";

            try {
                temp = File.createTempFile("selected_PSA", ".xml");
                String path_selectePSA = temp.getPath();
                path = Paths.get(path_selectePSA);

                if (Files.exists(path)) {
                    // file exist
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                try {

                    Files.write( Paths.get(path_selectePSA), sPSA_SG.getBytes(), StandardOpenOption.CREATE);
                    setPSA(path_selectePSA);

                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }


        if( refinementType.equals(RefinementType.APPLICATION_HSPL_SG)||  refinementType.equals(RefinementType.APPLICATION_MSPL_SG) ){
            //--
            //String path_sg = "/refinement/auxiliary_files/input/SG/SG.xml";

            try {
                temp = File.createTempFile("SGGGG", ".xml");

                String path_sg = temp.getPath();
                path = Paths.get(path_sg);

                if (Files.exists(path)) {
                    // file exist
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                try {

                    Files.write( Paths.get(path_sg), sPSA_SG.getBytes(), StandardOpenOption.CREATE);
                    setSG(path_sg);

                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }

        //--
        //String path_userPSA = "/refinement/auxiliary_files/input/PSA/user_PSA.xml";


        try {
            temp = File.createTempFile("user_PSA", ".xml");
            String path_userPSA = temp.getPath();
            path = Paths.get(path_userPSA);

            if (Files.exists(path)) {
                // file exist
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            try {

                Files.write( Paths.get(path_userPSA), userPSA.getBytes(), StandardOpenOption.CREATE);
                setUserPSA(path_userPSA);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        //--
        //String path_marketPSA = "/refinement/auxiliary_files/input/PSA/market_PSA.xml";

        try {
            temp = File.createTempFile("market_PSA", ".xml");
            String path_marketPSA = temp.getPath();
            path = Paths.get(path_marketPSA);


            if (Files.exists(path)) {
                // file exist
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            try {
                Files.write( Paths.get(path_marketPSA), additionalPSA.getBytes(), StandardOpenOption.CREATE);
                setAdditionalPSA(path_marketPSA);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        //--
        //String path_subject = "/refinement/auxiliary_files/input/Subject.xml";

        try {
            temp = File.createTempFile("Subject", ".xml");
            String path_subject = temp.getPath();
            path = Paths.get(path_subject);

            if (Files.exists(path)) {
                // file exist
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            try {

                Files.write( Paths.get(path_subject), subject_string.getBytes(), StandardOpenOption.CREATE);
                setSubject(path_subject);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        //--
        //String path_content = "/refinement/auxiliary_files/input/Content.xml";
        try {
            temp = File.createTempFile("Content", ".xml");
            String path_content = temp.getPath();
            path = Paths.get(path_content);

            if (Files.exists(path)) {
                // file exist
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            try {

                Files.write( Paths.get(path_content), content_string.getBytes(), StandardOpenOption.CREATE);
                setContent(path_content);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        //--
        //String path_target = "/refinement/auxiliary_files/input/Content.xml";
        try {
            temp = File.createTempFile("Content", ".xml");
            String path_target = temp.getPath();
            path = Paths.get(path_target);

            if (Files.exists(path)) {
                // file exist
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            try {

                Files.write( Paths.get(path_target), target_string.getBytes(), StandardOpenOption.CREATE);
                setTarget(path_target);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        optimizationType=OptimizationType.valueOf(optimizationType_string);
        maxEvaluationsNo=Integer.parseInt(maxEvaluationsNo_string);
    }


    public Configuration  (String path ){

        map=new Mapping();
        mspl_list=new HashSet<ITResource>();

        String schema_file,xml_file;

        schema_file="/refinement/schema/SchemaFile_Schema.xsd";
        xml_file="/refinement/auxiliary_files/input/Schemas.xml";
        Schemas schemas= (Schemas) Useful.unmashal(schema_file, xml_file, Schemas.class);
        String configuration_schema=schemas.getConfigurationSchema();
        Configurations conf=(Configurations) Useful.unmashal(configuration_schema, path, Configurations.class);

        refinementType=conf.getRefinementType();

        if(refinementType.equals(RefinementType.POLICY_HSPL)||
                refinementType.equals(RefinementType.APPLICATION_HSPL) ||
                refinementType.equals(RefinementType.APPLICATION_HSPL_SG) )
            setHSPL(conf.getHsplFile());


        if(! refinementType.equals(RefinementType.APPLICATION_HSPL_SG) &&  !refinementType.equals(RefinementType.APPLICATION_MSPL_SG) )
            setPSA(conf.getPsaFile());

        if( refinementType.equals(RefinementType.APPLICATION_HSPL_SG)||  refinementType.equals(RefinementType.APPLICATION_MSPL_SG) )
            setSG(conf.getSgInputFile());


        if( refinementType.equals(RefinementType.POLICY_MSPL)||
                refinementType.equals(RefinementType.APPLICATION_MSPL)||
                refinementType.equals(RefinementType.APPLICATION_MSPL_SG))
            addAllMSPL(conf.getMsplDirInput());


        setUserPSA(conf.getUserPsaFile());
        setAdditionalPSA(conf.getMarketPsaFile());
        setSubject(conf.getSubjectFile());
        setContent(conf.getContentFile());
        setTarget(conf.getTargetFile());
        optimizationType=conf.getOptimizationType();
        maxEvaluationsNo=conf.getMaxEvaluationsNo();





    }
    public void setRefinementType(RefinementType refimentType) {
        this.refinementType = refimentType;
    }
    public void setHSPL(String path){
        String	s_schema="/refinement/schema/Refinement_Schema.xsd";
        Mapping map_hspl=(Mapping) Useful.unmashal(s_schema, path, Mapping.class);
        
        for(Hspl h: map_hspl.getHsplList().getHspl() ){
			h.setSuitableImplementation(new SuitableImplementationList());
			h.setCapabilities(new CapabilityList());
			h.setCandidates(new Candidates());
		}
        map.setHsplList(map_hspl.getHsplList());

    }


    public void setPSA(String path){
        String	s_schema="/refinement/schema/Refinement_Schema.xsd";
        Mapping map_psa=(Mapping) Useful.unmashal(s_schema, path,Mapping.class );
        map.setPsaList(map_psa.getPsaList());
    }
    public void setUserPSA(String path){
        String	s_schema="/refinement/schema/Refinement_Schema.xsd";
        Mapping map_userPsa=(Mapping) Useful.unmashal(s_schema, path,Mapping.class );
        map.setUserPsaList(map_userPsa.getPsaList());
    }
    public void setAdditionalPSA(String path){
        String	s_schema="/refinement/schema/Refinement_Schema.xsd";
        Mapping map_marketPsa=(Mapping) Useful.unmashal(s_schema, path,Mapping.class );
        map.setAdditionalPsaList(map_marketPsa.getPsaList());
    }
    public void setSG(String path){
        String	s_schema="/refinement/schema/Refinement_Schema.xsd";
        Mapping map_sg=(Mapping) Useful.unmashal(s_schema, path,Mapping.class );
        map.setServiceGraph(map_sg.getServiceGraph());
    }
    public void addMSPL(String path){
        String	m_schema="/refinement/schema/MSPL_XML_Schema.xsd";
        ITResource it=(ITResource) Useful.unmashal(m_schema, path,ITResource.class );
        mspl_list.add(it);
    }
    public void addAllMSPL(String dir){
        String	m_schema="/refinement/schema/MSPL_XML_Schema.xsd";
        File folder = new File(dir);
        File[] listOfFiles = folder.listFiles();
        ITResource it=null;

        for(File f: listOfFiles){
            it=(ITResource) Useful.unmashal(m_schema, f.getPath(),ITResource.class );
            mspl_list.add(it);
        }
    }
    public void setSubject(String path){
        String a_schema="/refinement/schema/AssociationList_Schema.xsd";
        subject= (AssociationList) Useful.unmashal(a_schema,path , AssociationList.class);
    }
    public void setContent(String path){
        String a_schema="/refinement/schema/AssociationList_Schema.xsd";
        content= (AssociationList) Useful.unmashal(a_schema, path, AssociationList.class);
    }
    public void setTarget(String path){
        String a_schema="/refinement/schema/AssociationList_Schema.xsd";
        target= (AssociationList) Useful.unmashal(a_schema, path, AssociationList.class);
    }
    public void setMaxEvaluationsNo(int maxEvaluationsNo) {
        this.maxEvaluationsNo = maxEvaluationsNo;
    }
    public void setOptimizationType(OptimizationType optimizationType) {
        this.optimizationType = optimizationType;
    }

    public void mashalMSPLs(String dir){
        String path;
        for (ITResource i: mspl_list){
            RuleSetConfiguration c=(RuleSetConfiguration) i.getConfiguration();
            path=dir+c.getName()+".xml";
            Useful.mashal(i, path, ITResource.class );
        }
    }
    
    public HashSet<String> mashalMSPLs(){
    	HashSet<String> output=new HashSet<String>();
        for (ITResource i: mspl_list){
            RuleSetConfiguration c=(RuleSetConfiguration) i.getConfiguration();
            output.add(Useful.mashal2(i, ITResource.class ));
        }
        return output;
    }
    
    public void mashalSG(String path){
        Mapping map_sg=new Mapping();
        map_sg.setServiceGraph(map.getServiceGraph());
        Useful.mashal(map_sg, path, Mapping.class);
    }
    
    public String mashalSG(){
        Mapping map_sg=new Mapping();
        map_sg.setServiceGraph(map.getServiceGraph());
        return Useful.mashal2(map_sg, Mapping.class);
    }
    
    
    public void mashalMatching(String path){
        Useful.mashal(matching, path,Matching.class );
    }

    public void mashalRemediation(String path){
		Mapping map_rm=new Mapping();
		map_rm.setRemediation(map.getRemediation());
		Useful.mashal(map_rm, path, Mapping.class);
	}

    public String mashalRemediation(){
		Mapping map_rm=new Mapping();
		map_rm.setRemediation(map.getRemediation());
		return Useful.mashal2(map_rm, Mapping.class);
	}
	public String getEnforceableOutput(String sg_path, String matching_path, String mspls_dir ){
		String output="";

		try {
			output+=Useful.readFile_local_tmp(sg_path, Charset.defaultCharset());
			output+=Useful.readFile_local_tmp(matching_path, Charset.defaultCharset());
			File folder = new File(mspls_dir);
			folder.mkdir();
			File[] listOfFiles = folder.listFiles();
			for(File f: listOfFiles){
				output+=Useful.readFile_local_tmp(mspls_dir+f.getName(), Charset.defaultCharset());
			}


		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return output;
	}
	
	
	
	
	public String getNonEnforceableOutput(String remediation_path){
		String output="";
		try {
			output+=Useful.readFile(remediation_path, Charset.defaultCharset());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return output;
	}


    public Mapping getMap() {
        return map;
    }



    public void setMap(Mapping map) {
        this.map = map;
    }
    public RefinementType getRefinementType() {
        return refinementType;
    }




    public HashSet<ITResource> getMspl_list() {
        return mspl_list;
    }
    public void setMspl_list(HashSet<ITResource> mspl_list) {
        this.mspl_list = mspl_list;
    }
    public int getMaxEvaluationsNo() {
        return maxEvaluationsNo;
    }

    public OptimizationType getOptimizationType() {
        return optimizationType;
    }

    public Matching getMatching() {
        return matching;
    }
    public void setMatching(Matching matching) {
        this.matching = matching;
    }
    public AssociationList getSubject() {
        return subject;
    }
    public void setSubject(AssociationList subject) {
        this.subject = subject;
    }
    public AssociationList getContent() {
        return content;
    }



    public void setContent(AssociationList content) {
        this.content = content;
    }

    public AssociationList getTarget() {
        return target;
    }
    public void setTarget(AssociationList target) {
        this.target = target;
    }

}
