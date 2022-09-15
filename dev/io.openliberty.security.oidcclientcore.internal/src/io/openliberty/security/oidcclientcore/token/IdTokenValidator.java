/*******************************************************************************
 * Copyright (c) 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.security.oidcclientcore.token;

import io.openliberty.security.oidcclientcore.client.OidcClientConfig;
import io.openliberty.security.oidcclientcore.storage.OidcStorageUtils;

/**
 *
 */
public class IdTokenValidator extends TokenValidator {

    String nonce;
    String clientid;
    private String state;

    /**
     * @param clientConfig
     */
    public IdTokenValidator(OidcClientConfig clientConfig) {
        super(clientConfig);
        clientid = clientConfig.getClientId();
    }

    public IdTokenValidator nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }
    

    /**
     * @param string
     */
    public IdTokenValidator state(String state) {
        this.state = state;
        return this;
    }

    @Override
    public void validate() throws TokenValidationException {
        super.validate();
        validateNonce();

    }

    void validateNonce() throws TokenValidationException {
        // TODO : need access to Storage and state param value to compute nonce
        String cookieName = OidcStorageUtils.getNonceStorageKey(clientid, state);
    }


}
