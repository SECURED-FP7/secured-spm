package eu.fp7.secured.spm.impl;

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Future;

import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.MucaInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.MucaOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.MucaOutputBuilder;
//import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.muca.input.Coop;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.ReconciliationInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.ReconciliationOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.ReconciliationOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.ReconciliationService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucadInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucadOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucadOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucasInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucasOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.SucasOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.reconciliation.input.Coop;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.reconciliation.input.NonCoop;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.sucad.input.MSPL;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.fp7.secured.MultiUserConflictAnalysis.MultiUserConflictAnalysisHTML;
import eu.fp7.secured.SingleUserConflictAnalysis.SingleUserConflictAnalysisHTML;
import eu.fp7.secured.reconciliation.ReconciliationHTML;
import eu.fp7.secured.reconciliation.ReconciliationResult;


public class ReconciliationImpl implements ReconciliationService, Closeable{

    private static final Logger LOG = LoggerFactory.getLogger(ReconciliationImpl.class);

 // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 // Print the stack trace on the logs
    static public String getStackTrace(Throwable aThrowable) {
        Writer result = new StringWriter();
        PrintWriter printWriter = new PrintWriter(result);
        aThrowable.printStackTrace(printWriter);
        return result.toString();
    }
 // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 // Method called when the plugin is closed
    @Override
    public void close() throws IOException {
        LOG.info("Reconciliation Module Closed");
    }

 // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 // Reconciliation
//     input : {
//       coop : [
//           {"id":"1", "creator":"creator_id", "ag":"<xml>"},
//           {"id":"2", "creator":"creator_id", "ag":"<xml>"}
//       ],
//
//       non_coop : [
//           {"id":"1", "creator":"creator_id", "ag":"<xml>"},
//           {"id":"2", "creator":"creator_id", "ag":"<xml>"}
//       ],
//
//       MSPLs : ["<xml>", "<xml>", "<xml>"]
//      }
 //
//       output : {
//          MSPLs : ["<xml>", "<xml>", "<xml>"],
//          application_graph : "<xml>",
//          report : "<html>"
//       }

    @Override
    public Future<RpcResult<ReconciliationOutput>> reconciliation(ReconciliationInput input) {
        LinkedList<String> MSPL = new LinkedList<String>(input.getMSPL());

        ReconciliationOutputBuilder reconciliationOutput = new ReconciliationOutputBuilder();
        try {

            LinkedList<String> coop_application_graph_creator = new LinkedList<String>();
            LinkedList<String> coop_application_graph = new LinkedList<String>();
            for (Coop i: input.getCoop()){
                coop_application_graph_creator.add(i.getCreator());
                coop_application_graph.add(i.getAg());
            }

            LinkedList<String> non_coop_application_graph_creator = new LinkedList<String>();
            LinkedList<String> non_coop_application_graph = new LinkedList<String>();
            for (NonCoop i: input.getNonCoop()){
                non_coop_application_graph_creator.add(i.getCreator());
                non_coop_application_graph.add(i.getAg());
            }
            ReconciliationResult reconcile = ReconciliationHTML.reconcile(coop_application_graph_creator,
                    coop_application_graph, non_coop_application_graph_creator,
                    non_coop_application_graph, MSPL);

            // #####################
            // setting the return values
            reconciliationOutput.setApplicationGraph(reconcile.app_graph);
            reconciliationOutput.setReport(reconcile.report);
            reconciliationOutput.setMSPL(new ArrayList<String>(reconcile.MSPLs));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            LOG.error(getStackTrace(e));
        }
        return RpcResultBuilder.<ReconciliationOutput>success(reconciliationOutput.build()).buildFuture();
    }

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// MUCA multi-user-conflict-analysis Implementation
//  "input": {
//  "coop": [
    //     {"id":"1", "creator":"creator_id", "ag":"<xml>"},
    //     {"id":"2", "creator":"creator_id", "ag":"<xml>"}
    //   ],
    //
    // MSPLs : ["<xml>", "<xml>", "<xml>"]
    //}
    //
    //"output": {
    //   "report": ""
    //}
    @Override
    public Future<RpcResult<MucaOutput>> muca(MucaInput input) {
        LinkedList<String> MSPL = new LinkedList<String>(input.getMSPL());
        MucaOutputBuilder mucaOutput = new MucaOutputBuilder();

        try {

            LinkedList<String> coop_application_graph_creator = new LinkedList<String>();
            LinkedList<String> coop_application_graph = new LinkedList<String>();
            for (org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.muca.input.Coop i: input.getCoop()){
                coop_application_graph_creator.add(i.getCreator());
                coop_application_graph.add(i.getAg());
            }

            String report = MultiUserConflictAnalysisHTML.analyse(coop_application_graph_creator,
                    coop_application_graph, MSPL);

            // #####################
            // setting the return values
            mucaOutput.setReport(report);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            LOG.error(getStackTrace(e));
        }
        return RpcResultBuilder.<MucaOutput>success(mucaOutput.build()).buildFuture();
    }

//  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//  single-user-conflict-analysis of one policy
//     "input": {
//         "MSPL": ""
//     }
//
//     "output": {
//         "report": ""
//     }
    @Override
    public Future<RpcResult<SucasOutput>> sucas(SucasInput input) {
        String MSPL = input.getMSPL();
        SucasOutputBuilder sucasOutput = new SucasOutputBuilder();

        try {
            String report = SingleUserConflictAnalysisHTML.analyseSP(MSPL);

            // #####################
            // setting the return values
            sucasOutput.setReport(report);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            LOG.error(getStackTrace(e));
        }
        return RpcResultBuilder.<SucasOutput>success(sucasOutput.build()).buildFuture();
    }

//  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//  single-user-conflict-analysis of all policies
//  "input": {
//  MSPLs : [
//      {"id":"1" "mspl":"<xml>"},
//      {"id":"2" "mspl":"<xml>"},
//      {"id":"3" "mspl":"<xml>"}
//    ]
//}
//
//"output": {
// "report": ""
//}
    @Override
    public Future<RpcResult<SucadOutput>> sucad(SucadInput input) {

        SucadOutputBuilder sucadOutput = new SucadOutputBuilder();
        try {
            List<String> MSPL = new ArrayList<String>();
            for (MSPL i : input.getMSPL()){
                MSPL.add(i.getMspl());
            }
            String report = SingleUserConflictAnalysisHTML.analyseMP(MSPL);

            // #####################
            // setting the return values
            sucadOutput.setReport(report);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            LOG.error(getStackTrace(e));
        }
        return RpcResultBuilder.<SucadOutput>success(sucadOutput.build()).buildFuture();
    }

}
