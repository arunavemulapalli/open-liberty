/*******************************************************************************
 * Copyright (c) 2017, 2018 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.microprofile.openapi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.eclipse.microprofile.openapi.OASFilter;
import org.eclipse.microprofile.openapi.OASModelReader;
import org.eclipse.microprofile.openapi.models.OpenAPI;
import org.eclipse.microprofile.openapi.models.Operation;
import org.eclipse.microprofile.openapi.models.Paths;
import org.eclipse.microprofile.openapi.models.servers.Server;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.container.service.app.deploy.ApplicationInfo;
import com.ibm.ws.container.service.app.deploy.EARApplicationInfo;
import com.ibm.ws.container.service.app.deploy.WebModuleInfo;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.microprofile.openapi.impl.core.util.Json;
import com.ibm.ws.microprofile.openapi.impl.core.util.Yaml;
import com.ibm.ws.microprofile.openapi.impl.jaxrs2.Reader;
import com.ibm.ws.microprofile.openapi.impl.model.OpenAPIImpl;
import com.ibm.ws.microprofile.openapi.impl.model.PathsImpl;
import com.ibm.ws.microprofile.openapi.impl.model.info.InfoImpl;
import com.ibm.ws.microprofile.openapi.impl.model.servers.ServerImpl;
import com.ibm.ws.microprofile.openapi.impl.parser.OpenAPIV3Parser;
import com.ibm.ws.microprofile.openapi.impl.parser.core.models.SwaggerParseResult;
import com.ibm.ws.microprofile.openapi.impl.validation.OASValidationResult;
import com.ibm.ws.microprofile.openapi.impl.validation.OASValidationResult.ValidationEvent.Severity;
import com.ibm.ws.microprofile.openapi.impl.validation.OASValidator;
import com.ibm.ws.microprofile.openapi.utils.OpenAPIUtils;
import com.ibm.ws.microprofile.openapi.utils.ProxySupportUtil;
import com.ibm.ws.microprofile.openapi.utils.ServerInfo;
import com.ibm.wsspi.adaptable.module.Container;
import com.ibm.wsspi.adaptable.module.Entry;
import com.ibm.wsspi.adaptable.module.UnableToAdaptException;
import com.ibm.wsspi.http.VirtualHost;

/**
 *
 */
@Component(service = { ApplicationProcessor.class }, configurationPolicy = ConfigurationPolicy.IGNORE, immediate = true, property = { "service.vendor=IBM" })
public class ApplicationProcessor {

    private static final TraceComponent tc = Tr.register(ApplicationProcessor.class);

    enum DocType {
        JSON,
        YAML
    }

    private static ApplicationProcessor instance;
    private OpenAPI document = null;
    private static ApplicationInfo currentApp = null;
    private static Map<String, ApplicationInfo> applications = new HashMap<>();
    private final ServerInfo serverInfo = new ServerInfo();

    public void activate(ComponentContext cc) {
        instance = this;
        if (currentApp != null) {
            this.document = createBaseOpenAPIDocument();
            processApplication(currentApp);
        } else {
            this.document = createBaseOpenAPIDocument();
        }
    }

    public void addApplication(ApplicationInfo appInfo) {
        synchronized (this.document) {
            if (currentApp == null) {
                processApplication(appInfo);
            } else {
                applications.put(appInfo.getName(), appInfo);
            }
        }
    }

    private OpenAPI processWebModule(Container appContainer, WebModuleInfo moduleInfo) {
        ClassLoader appClassloader = moduleInfo.getClassLoader();
        boolean isOASApp = false;

        //read and process the MicroProfile config
        ConfigProcessor configProcessor = new ConfigProcessor(appClassloader);

        OpenAPI newDocument = null;
        //Retrieve model from model reader
        OASModelReader modelReader = OpenAPIUtils.getOASModelReader(appClassloader, configProcessor.getModelReaderClassName());
        if (modelReader != null) {
            try {
                OpenAPI model = modelReader.buildModel();
                if (model != null) {
                    isOASApp = true;
                    newDocument = model;
                }
            } catch (Throwable e) {
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(tc, "Failed to construct model from the application: " + e.getMessage());
                }
            }
        }

        //Retrieve OpenAPI document as a string
        String openAPIStaticFile = StaticFileProcessor.getOpenAPIFile(appContainer);
        if (openAPIStaticFile != null) {
            SwaggerParseResult result = new OpenAPIV3Parser().readContents(openAPIStaticFile, newDocument, null, null);
            if (result.getOpenAPI() != null) {
                newDocument = result.getOpenAPI();
                isOASApp = true;
            } else {
                Tr.error(tc, "OPENAPI_FILE_PARSE_ERROR", moduleInfo.getApplicationInfo().getDeploymentName());
            }
        }

        //Scan for annotated classes
        AnnotationScanner scanner = OpenAPIUtils.creatAnnotationScanner(appClassloader, appContainer);
        if (!configProcessor.isScanDisabled()) {

            Set<String> classNamesToScan = new HashSet<>();
            if (configProcessor.getClassesToScan() != null) {
                classNamesToScan.addAll(configProcessor.getClassesToScan());
            }

            if (configProcessor.getPackagesToScan() != null) {
                Set<String> foundClasses = scanner.getAnnotatedClassesNames();
                for (String packageName : configProcessor.getPackagesToScan()) {
                    for (String className : foundClasses) {
                        if (className.startsWith(packageName)) {
                            classNamesToScan.add(className);
                        }
                    }
                }
            }

            if (classNamesToScan.size() == 0 && scanner.anyAnnotatedClasses()) {
                classNamesToScan.addAll(scanner.getAnnotatedClassesNames());
            }
            if (configProcessor.getClassesToExclude() != null) {
                classNamesToScan.removeAll(configProcessor.getClassesToExclude());
            }
            if (configProcessor.getPackagesToExclude() != null) {
                for (String packageToExclude : configProcessor.getPackagesToExclude()) {
                    Iterator<String> iterator = classNamesToScan.iterator();
                    while (iterator.hasNext()) {
                        if (iterator.next().startsWith(packageToExclude)) {
                            iterator.remove();
                        }
                    }
                }
            }

            if (classNamesToScan.size() > 0) {
                isOASApp = true;
                Set<Class<?>> classes = new HashSet<>();
                for (String clazz : classNamesToScan) {
                    try {
                        classes.add(appClassloader.loadClass(clazz));
                    } catch (ClassNotFoundException e) {
                        if (OpenAPIUtils.isEventEnabled(tc)) {
                            Tr.event(tc, "Failed to load class: " + e.getMessage());
                        }
                    }
                }
                Reader reader = new Reader(newDocument);
                reader.setApplicationPath(scanner.getURLMapping());
                newDocument = reader.read(classes);
            }
        }

        if (!isOASApp) {
            return null;
        }

        // Handle servers specified in configuration (before filtering)
        handleServers(newDocument, configProcessor);

        // Filter
        OASFilter oasFilter = OpenAPIUtils.getOASFilter(appClassloader, configProcessor.getOpenAPIFilterClassName());

        if (oasFilter != null) {
            final OpenAPIFilter filter = new OpenAPIFilter(oasFilter);
            try {
                filter.filter(newDocument);
            } catch (Throwable e) {
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(tc, "Failed to call OASFilter: " + e.getMessage());
                }
            }
        }

        // Validate the document if the validation property has been enabled.
        final boolean validating = configProcessor.isValidating();
        if (validating) {
            try {
                validateDocument(newDocument);
            } catch (Throwable e) {
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(tc, "Failed to call OASValidator: " + e.getMessage());
                }
            }
        }

        return newDocument;
    }

    private void validateDocument(OpenAPI document) {
        final OASValidator validator = new OASValidator();
        final OASValidationResult result = validator.validate(document);
        if (result.hasEvents()) {
            result.getEvents().stream().forEach(v -> {
                if (v.severity == Severity.ERROR) {
                    Tr.error(tc, "OPENAPI_DOCUMENT_VALIDATION_ERROR", v.message, v.location);
                } else if (v.severity == Severity.WARNING) {
                    Tr.warning(tc, "OPENAPI_DOCUMENT_VALIDATION_WARNING", v.message, v.location);
                }
            });
        }
    }

    @FFDCIgnore(UnableToAdaptException.class)
    private void processApplication(ApplicationInfo appInfo) {
        synchronized (this.document) {

            if (appInfo == null) {
                return;
            }

            Container appContainer = appInfo.getContainer();
            if (appContainer == null) {
                return;
            }

            WebModuleInfo moduleInfo = null;
            if (appInfo instanceof EARApplicationInfo) {
                for (Entry entry : appContainer) {
                    try {
                        Container c = entry.adapt(Container.class);
                        if (c != null) {
                            WebModuleInfo wmi = OpenAPIUtils.getWebModuleInfo(c);
                            if (wmi != null) {
                                OpenAPI openAPI = processWebModule(c, wmi);
                                if (openAPI != null) {
                                    currentApp = appInfo;
                                    this.document = openAPI;
                                    handleApplicationPath(openAPI, wmi.getContextRoot());
                                    handleUserServer(openAPI);
                                    break;
                                }
                            }
                        }

                    } catch (UnableToAdaptException e) {
                        if (OpenAPIUtils.isDebugEnabled(tc)) {
                            Tr.debug(tc, "Failed to adapt entry: " + e.getMessage());
                        }
                    }
                }
            } else {
                moduleInfo = OpenAPIUtils.getWebModuleInfo(appContainer);
            }

            if (moduleInfo == null) {
                return;
            }

            OpenAPI openAPI = processWebModule(appContainer, moduleInfo);
            if (openAPI != null) {
                currentApp = appInfo;
                handleApplicationPath(openAPI, moduleInfo.getContextRoot());
                handleUserServer(openAPI);
                this.document = openAPI;
            }
        }
    }

    private void handleApplicationPath(final OpenAPI openAPI, String contextRoot) {
        //Check the first path item to determine if it already starts with contextRoot
        if (openAPI != null) {
            Paths paths = openAPI.getPaths();
            if (paths != null && !paths.isEmpty() && paths.keySet().iterator().next().startsWith(contextRoot)) {
                if (OpenAPIUtils.isDebugEnabled(tc)) {
                    Tr.debug(tc, "Path already starts with context root: " + contextRoot);
                }
                return; //no-op
            }
        }

        //Path doesn't start with context root, so add it
        serverInfo.setApplicationPath(contextRoot);
    }

    private void handleUserServer(final OpenAPI openapi) {
        if (openapi != null && openapi.getServers() != null && openapi.getServers().size() > 0) {
            serverInfo.setIsUserServer(true);
        }
    }

    private void handleServers(OpenAPI openapi, ConfigProcessor configProcessor) {

        // Handle global servers
        Set<String> servers = configProcessor.getServers();
        if (servers != null && servers.size() > 0) {
            List<Server> configServers = new ArrayList<Server>();
            for (String server : servers) {
                configServers.add(new ServerImpl().url(server.trim()));
            }

            if (configServers.size() > 0) {
                openapi.setServers(configServers);
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(tc, "Set global servers from config: " + configServers);
                }
            }
        }

        // Handle servers for paths and operations
        Map<String, Set<String>> pathServers = configProcessor.getPathsServers();
        Map<String, Set<String>> operationServers = configProcessor.getOperationsServers();

        // if no servers for paths/operations were specified then quickly exit
        if ((pathServers == null || pathServers.isEmpty()) && (operationServers == null || operationServers.isEmpty())) {
            if (OpenAPIUtils.isDebugEnabled(tc)) {
                Tr.debug(tc, "Servers for paths/operations were not specified, so return");
            }
            return;
        }

        Paths paths = openapi.getPaths();
        if (paths != null && !paths.isEmpty()) {
            for (String path : paths.keySet()) {

                // Set the alternative servers (if any) on path
                if (pathServers != null && pathServers.containsKey(path)) {
                    List<Server> configPathServers = new ArrayList<Server>();
                    for (String server : pathServers.get(path)) {
                        configPathServers.add(new ServerImpl().url(server.trim()));
                    }
                    if (!configPathServers.isEmpty()) {
                        paths.get(path).setServers(configPathServers);
                    }
                }

                // Set the alternative servers (if any) on operation
                if (operationServers != null) {
                    for (Operation operation : paths.get(path).readOperations()) {
                        String operationId = operation.getOperationId();
                        if (operationId != null && operationServers.containsKey(operationId)) {
                            List<Server> configOperationServers = new ArrayList<Server>();
                            for (String server : operationServers.get(operationId)) {
                                configOperationServers.add(new ServerImpl().url(server.trim()));
                            }
                            if (!configOperationServers.isEmpty()) {
                                operation.setServers(configOperationServers);
                            }
                        }
                    }
                }

            }
        }
    }

    public void removeApplication(ApplicationInfo appInfo) {

        synchronized (this.document) {
            if (currentApp != null && currentApp.getName().equals(appInfo.getName())) {
                currentApp = null;
                this.serverInfo.setApplicationPath(null);
                this.serverInfo.setIsUserServer(false);
                this.document = createBaseOpenAPIDocument();
                Iterator<java.util.Map.Entry<String, ApplicationInfo>> iterator = applications.entrySet().iterator();
                while (iterator.hasNext()) {
                    java.util.Map.Entry<String, ApplicationInfo> entry = iterator.next();
                    processApplication(entry.getValue());
                    iterator.remove();
                    if (currentApp != null) {
                        break;
                    }
                }
            } else {
                applications.remove(appInfo.getName());
            }
        }
    }

    @FFDCIgnore(JsonProcessingException.class)
    public String getOpenAPIDocument(HttpServletRequest request, DocType docType) {
        String oasResult = null;
        synchronized (this.document) {
            ServerInfo reqServerInfo = null;
            synchronized (serverInfo) {
                reqServerInfo = new ServerInfo(serverInfo);
            }
            ProxySupportUtil.processRequest(request, reqServerInfo);
            reqServerInfo.updateOpenAPIWithServers(this.document);
            try {
                if (DocType.YAML == docType) {
                    oasResult = Yaml.mapper().writeValueAsString(this.document);
                } else {
                    oasResult = Json.mapper().writeValueAsString(this.document);
                }
            } catch (JsonProcessingException e) {
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(this, tc, "Failed to serialize OpenAPI docuemnt: " + e.getMessage());
                }
            }
        }
        return oasResult;
    }

    private OpenAPI createBaseOpenAPIDocument() {
        OpenAPI openAPI = new OpenAPIImpl();
        openAPI.info(new InfoImpl().title("Liberty APIs").version("1.0"));
        openAPI.paths(new PathsImpl());
        return openAPI;
    }

    @Reference(service = VirtualHost.class, target = "(&(enabled=true)(id=default_host)(|(aliases=*)(httpsAlias=*)))", policy = ReferencePolicy.STATIC, cardinality = ReferenceCardinality.MANDATORY)
    protected void setVirtualHost(VirtualHost vhost, Map<String, Object> props) {
        updateOpenAPIServer(vhost, props);
    }

    protected void updatedVirtualHost(VirtualHost vhost, Map<String, Object> props) {
        updateOpenAPIServer(vhost, props);
    }

    private void updateOpenAPIServer(VirtualHost vhost, Map<String, Object> props) {

        Object value = props.get("httpsAlias");
        if (value == null) {
            String[] aliases = (String[]) props.get("aliases");
            if (OpenAPIUtils.isDebugEnabled(tc)) {
                Tr.debug(this, tc, "httpsAlias is null. aliases : " + String.join(", ", aliases));
            }
            value = Arrays.stream(aliases).filter(a -> !a.endsWith(":-1")).findFirst().orElse(null);
            if (OpenAPIUtils.isDebugEnabled(tc)) {
                Tr.debug(this, tc, "Found non-secure alias: " + value);
            }
        }

        String alias = String.valueOf(value);

        if (OpenAPIUtils.isEventEnabled(tc)) {
            Tr.event(this, tc, "Received new alias: " + alias);
        }

        synchronized (this.serverInfo) {
            serverInfo.setHttpPort(vhost.getHttpPort(alias));
            serverInfo.setHttpsPort(vhost.getSecureHttpPort(alias));
            serverInfo.setHost(vhost.getHostName(alias));
            checkVCAPHost(serverInfo);
        }

        if (OpenAPIUtils.isEventEnabled(tc)) {
            Tr.event(this, tc, "Updated server information: " + serverInfo);
        }
    }

    /**
     * This method check the environment variable"VCAP_APPLICATION", which in Cloud Foundry (where Bluemix runs)
     * will be set to the actual host that is visible to the user. In that environment the VHost from Liberty
     * is private and not accessible externally.
     */
    @FFDCIgnore(Exception.class)
    private void checkVCAPHost(ServerInfo server) {
        String VCAP_APPLICATION = System.getenv("VCAP_APPLICATION");
        if (VCAP_APPLICATION != null) {
            try {
                JsonNode node = Json.mapper().readValue(VCAP_APPLICATION, JsonNode.class);
                ArrayNode uris = (ArrayNode) node.get("uris");
                if (uris != null && uris.size() > 0 && uris.get(0) != null) {
                    server.setHost(uris.get(0).textValue());
                }

                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(this, tc, "Changed hostPort using VCAP_APPLICATION.  New value: " + server.getHost());
                }
            } catch (Exception e) {
                if (OpenAPIUtils.isEventEnabled(tc)) {
                    Tr.event(this, tc, "Exception while parsing VCAP_APPLICATION env: " + e.getMessage());
                }
            }
        }
    }

    /**
     * @return the instance
     */
    public static ApplicationProcessor getInstance() {
        return instance;
    }
}
