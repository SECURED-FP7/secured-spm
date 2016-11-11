/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.h2mservice.impl;

import org.junit.Test;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker;

import static org.mockito.Mockito.mock;

public class H2mserviceProviderTest {
    @Test
    public void testOnSessionInitiated() {
        H2mserviceProvider provider = new H2mserviceProvider();

        // ensure no exceptions
        // currently this method is empty
        provider.onSessionInitiated(mock(BindingAwareBroker.ProviderContext.class));
    }

    @Test
    public void testClose() throws Exception {
        H2mserviceProvider provider = new H2mserviceProvider();

        // ensure no exceptions
        // currently this method is empty
        provider.close();
    }
}
