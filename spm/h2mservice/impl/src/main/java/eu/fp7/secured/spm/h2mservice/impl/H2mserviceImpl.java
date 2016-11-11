package eu.fp7.secured.spm.h2mservice.impl;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.Future;

import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.rev150105.H2mrefinementInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.rev150105.H2mrefinementOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.rev150105.H2mrefinementOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.rev150105.H2mserviceService;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import main.java.refinement_class.Output_Refinement;

public class H2mserviceImpl implements H2mserviceService, Closeable{
    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);

    @Override
    public Future<RpcResult<H2mrefinementOutput>> h2mrefinement(H2mrefinementInput input) {
        // TODO Auto-generated method stub
        String refinemtType = input.getRefinementType();
        String hspl_mspl = input.getHsplMspl();
        String sPSA_SG = input.getSPSASG();
        String userPSA = input.getUserPSA();
        String marketPSA = input.getMarketPSA();
        String subject_string = input.getSubjectString();
        String content_string = input.getContentString();
        String target_string = input.getTargetString();
        String optimizationType_string = input.getOptimizationTypeString();
        String maxEvaluationsNo_string = input.getMaxEvaluationsNoString();


//        String result = main.java.refinement_class.Refinement.test(option);
        Output_Refinement output_refinement = main.java.refinement_class.Refinement.run2(refinemtType,
                hspl_mspl, sPSA_SG, userPSA, marketPSA, subject_string, content_string,
                target_string, optimizationType_string, maxEvaluationsNo_string);

        H2mrefinementOutputBuilder refinementOutput = new H2mrefinementOutputBuilder();

        // #####################
        // setting the return values
        refinementOutput.setApplicationGraph(output_refinement.getApplication_grap());
        refinementOutput.setRemediation(output_refinement.getRemediation());
        refinementOutput.setMSPL(new ArrayList<String>(output_refinement.getMspls()));

        return RpcResultBuilder.<H2mrefinementOutput>success(refinementOutput.build()).buildFuture();
    }

    @Override
    public void close() throws IOException {
        // TODO Auto-generated method stub

    }
}
