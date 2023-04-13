/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.saml.sso20.internal;

import com.ibm.ws.security.common.structures.LocalCache;
import javax.cache.Cache;

import io.openliberty.jcache.CacheService;

/**
 *
 */
public class JCacheACSCache extends LocalCache {

    CacheService cacheService = null;
    /**
     * @param cacheService
     * @param ssoServiceImpl
     */
    public JCacheACSCache(CacheService cacheService) {
        super(0,0);
        this.cacheService = cacheService;
    }
    
    /**
     * 
     */
    public JCacheACSCache() {
        super(0,0);
    }

    public boolean isJCache() {
        return this.cacheService != null;
    }
    
    public javax.cache.Cache<Object, Object> getJCache() {
        javax.cache.Cache<Object, Object> jCache = null;
        if (cacheService != null) {
            jCache = cacheService.getCache();
        }

        return jCache;
    }

}
