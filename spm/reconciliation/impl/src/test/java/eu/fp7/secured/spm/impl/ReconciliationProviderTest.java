/*
 * SECURED and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package eu.fp7.secured.spm.impl;

import org.junit.Test;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker;

import static org.mockito.Mockito.mock;

public class ReconciliationProviderTest {
    @Test
    public void testOnSessionInitiated() {
        ReconciliationProvider provider = new ReconciliationProvider();

        // ensure no exceptions
        // currently this method is empty
        provider.onSessionInitiated(mock(BindingAwareBroker.ProviderContext.class));
    }

    @Test
    public void testClose() throws Exception {
        ReconciliationProvider provider = new ReconciliationProvider();

        // ensure no exceptions
        // currently this method is empty
        provider.close();
    }
}
