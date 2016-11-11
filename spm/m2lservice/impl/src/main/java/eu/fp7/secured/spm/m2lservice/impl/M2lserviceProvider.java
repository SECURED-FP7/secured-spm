/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.m2lservice.impl;

import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.RpcRegistration;
import org.opendaylight.controller.sal.binding.api.BindingAwareProvider;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.m2lservice.rev150105.M2lserviceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class M2lserviceProvider implements BindingAwareProvider, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(M2lserviceProvider.class);
    private RpcRegistration<M2lserviceService> m2lserviceService;
    private M2lserviceImpl m2lserviceImpl;

    @Override
    public void onSessionInitiated(ProviderContext session) {
        LOG.info("M2lserviceProvider Session Initiated");
        m2lserviceImpl = new M2lserviceImpl();
        m2lserviceService = session.addRpcImplementation(M2lserviceService.class, m2lserviceImpl);
    }

    @Override
    public void close() throws Exception {
        LOG.info("M2lserviceProvider Closed");
        if(m2lserviceService != null) {
            m2lserviceService.close();
        }
        if (m2lserviceImpl != null){
            m2lserviceImpl.close();
        }
    }
}
