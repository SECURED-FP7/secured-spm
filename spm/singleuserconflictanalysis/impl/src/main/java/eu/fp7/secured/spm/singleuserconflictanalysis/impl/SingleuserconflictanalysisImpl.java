package eu.fp7.secured.spm.singleuserconflictanalysis.impl;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.xml.bind.JAXBException;

import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.singleuserconflictanalysis.rev150105.AnalyseInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.singleuserconflictanalysis.rev150105.AnalyseOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.singleuserconflictanalysis.rev150105.AnalyseOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.singleuserconflictanalysis.rev150105.SingleuserconflictanalysisService;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.tools.Analyzer;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.utils.HTMLView;

public class SingleuserconflictanalysisImpl implements SingleuserconflictanalysisService {

    private static final Logger LOG = LoggerFactory.getLogger(SingleuserconflictanalysisImpl.class);
    private final ExecutorService executor;

    public SingleuserconflictanalysisImpl() {
        executor = Executors.newCachedThreadPool();
    }

    @Override
    public ListenableFuture<RpcResult<AnalyseOutput>> analyse(AnalyseInput input) {

        final SettableFuture<RpcResult<AnalyseOutput>> futureResult = SettableFuture.create();

        executor.submit(new AnalyseTask(input, futureResult));

        return futureResult;
    }

    private class AnalyseTask implements Callable<Void> {

        final AnalyseInput input;
        final SettableFuture<RpcResult<AnalyseOutput>> futureResult;

        public AnalyseTask(final AnalyseInput input, final SettableFuture<RpcResult<AnalyseOutput>> futureResult) {
            this.input = input;
            this.futureResult = futureResult;
        }

        @Override
        public Void call() {

            AnalyseOutputBuilder out = new AnalyseOutputBuilder();
            RpcResultBuilder<AnalyseOutput> rpcResult;

            try {
                String outFile = input.getOutputFile();
                String inFile = input.getInputFile();

                if (outFile == null || inFile == null) {
                    throw new Exception("Both input-file and output-file parameters must be specified.");
                }

                LOG.info("SingleUserConflictAnalysis:Analyse invoked." + "\n\tReading policy : " + inFile
                        + "\n\tSave report to : " + outFile);

                Policy policy;
                policy = PolicyWrapper.getFilteringPolicy(new File(inFile));
                LinkedList<Policy> p_list = new LinkedList<Policy>();
                p_list.add(policy);

                HTMLView.createHTMLView(outFile, singleAnalysis(policy), p_list, null, "SUCAS",
                        "Single User Conflict Analysis Report", "Single User Conflict Analysis Staticstics");

                out.setStatusCode(0);
                out.setStatusMessage("Calculation completed. Report is at " + outFile);
                LOG.info("Calculation completed. Report is at " + outFile);

            } catch (JAXBException | InvalidActionException | IncompatibleResolutionTypeException
                    | InvalidIpAddressException | InvalidRangeException | IncompatibleSelectorException
                    | IncompatibleExternalDataException | DuplicateExternalDataException | UnsupportedSelectorException
                    | InvalidNetException | NoExternalDataException e) {

                LOG.error(getStackTrace(e));
                out.setStatusCode(1);
                out.setStatusMessage(e.getClass().getSimpleName() + ": " + e.getMessage());
            } catch (Exception e) {
                LOG.error(getStackTrace(e));
                out.setStatusCode(1);
                out.setStatusMessage(e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            rpcResult = RpcResultBuilder.<AnalyseOutput> success(out.build());

            futureResult.set(rpcResult.build());

            return null;
        }

        private Set<PolicyAnomaly> singleAnalysis(Policy policy) throws Exception {

            SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

            Analyzer analyzer = new Analyzer();
            Set<PolicyAnomaly> anomalies = analyzer.getSingleAnomalies(policy, selectorTypes);

            return anomalies;
        }

        public String getStackTrace(Throwable aThrowable) {
            Writer result = new StringWriter();
            PrintWriter printWriter = new PrintWriter(result);
            aThrowable.printStackTrace(printWriter);
            return result.toString();
        }
    }

    public void stopExecutor() {
        executor.shutdown();
        while (!executor.isShutdown()) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

}
