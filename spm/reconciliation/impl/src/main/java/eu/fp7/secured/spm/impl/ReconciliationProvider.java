/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.impl;

import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.RpcRegistration;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.reconciliation.rev150105.ReconciliationService;
import org.opendaylight.controller.sal.binding.api.BindingAwareProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ReconciliationProvider implements BindingAwareProvider, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(ReconciliationProvider.class);
    private RpcRegistration<ReconciliationService> reconciliationService;
    private ReconciliationImpl reconciliationImpl;

    @Override
    public void onSessionInitiated(ProviderContext session) {
        LOG.info("ReconciliationProvider Session Initiated");
        reconciliationImpl = new ReconciliationImpl();
        reconciliationService = session.addRpcImplementation(ReconciliationService.class, reconciliationImpl);
    }

    @Override
    public void close() throws Exception {
        LOG.info("ReconciliationProvider Closed");
        if(reconciliationService != null) {
            reconciliationService.close();
        }
        if (reconciliationImpl != null){
            reconciliationImpl.close();
        }
    }

}
