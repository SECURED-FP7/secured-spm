/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.impl.rev141210;

import eu.fp7.secured.spm.h2mservice.impl.H2mserviceProvider;

public class H2mserviceModule extends org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.impl.rev141210.AbstractH2mserviceModule {
    public H2mserviceModule(org.opendaylight.controller.config.api.ModuleIdentifier identifier, org.opendaylight.controller.config.api.DependencyResolver dependencyResolver) {
        super(identifier, dependencyResolver);
    }

    public H2mserviceModule(org.opendaylight.controller.config.api.ModuleIdentifier identifier, org.opendaylight.controller.config.api.DependencyResolver dependencyResolver, org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.h2mservice.impl.rev141210.H2mserviceModule oldModule, java.lang.AutoCloseable oldInstance) {
        super(identifier, dependencyResolver, oldModule, oldInstance);
    }

    @Override
    public void customValidation() {
        // add custom validation form module attributes here.
    }

    @Override
    public java.lang.AutoCloseable createInstance() {
        H2mserviceProvider provider = new H2mserviceProvider();
        getBrokerDependency().registerProvider(provider);
        return provider;
    }

}
