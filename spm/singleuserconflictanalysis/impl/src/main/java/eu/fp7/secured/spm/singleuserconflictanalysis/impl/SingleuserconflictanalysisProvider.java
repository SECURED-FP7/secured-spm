/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.singleuserconflictanalysis.impl;

import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.RpcRegistration;
import org.opendaylight.controller.sal.binding.api.BindingAwareProvider;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.singleuserconflictanalysis.rev150105.SingleuserconflictanalysisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SingleuserconflictanalysisProvider implements BindingAwareProvider, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(SingleuserconflictanalysisProvider.class);
    private RpcRegistration<SingleuserconflictanalysisService> sucaService;
    private SingleuserconflictanalysisImpl sucaImpl;

    @Override
    public void onSessionInitiated(ProviderContext session) {
        LOG.info("SingleuserconflictanalysisProvider Session Initiated");
        sucaImpl = new SingleuserconflictanalysisImpl();
        sucaService = session.addRpcImplementation(SingleuserconflictanalysisService.class, sucaImpl);
    }

    @Override
    public void close() throws Exception {
        LOG.info("SingleuserconflictanalysisProvider Closed");
        if(sucaService != null) {
            sucaService.close();
        }
        sucaImpl.stopExecutor();
    }

}
