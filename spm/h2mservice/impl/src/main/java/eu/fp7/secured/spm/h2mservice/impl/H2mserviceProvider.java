/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.h2mservice.impl;

import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.ProviderContext;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.RpcRegistration;
import org.opendaylight.controller.sal.binding.api.BindingAwareProvider;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.rev150105.H2mserviceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class H2mserviceProvider implements BindingAwareProvider, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceProvider.class);
    private RpcRegistration<H2mserviceService> h2mserviceService;
    private H2mserviceImpl h2mserviceImpl;

    @Override
    public void onSessionInitiated(ProviderContext session) {
        LOG.info("H2mserviceProvider Session Initiated");
        h2mserviceImpl = new H2mserviceImpl();
        h2mserviceService = session.addRpcImplementation(H2mserviceService.class, h2mserviceImpl);
    }

    @Override
    public void close() throws Exception {
        LOG.info("H2mserviceProvider Closed");
        if(h2mserviceService != null) {
            h2mserviceService.close();
        }
        if (h2mserviceImpl != null){
            h2mserviceImpl.close();
        }
    }

}
