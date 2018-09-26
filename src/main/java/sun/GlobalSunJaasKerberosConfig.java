/*
 * Copyright 2010-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sun;

import javax.annotation.PostConstruct;

/**
 * Config for global jaas.
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class GlobalSunJaasKerberosConfig {

    private boolean debug = false;

    private String krbConfLocation;

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        if (debug) {
            System.setProperty("sun.security.krb5.debug", "true");
        }
        if (krbConfLocation != null) {
            System.setProperty("java.security.krb5.conf", krbConfLocation);
        }

    }

    /**
     * Enable debug logs from the Sun Kerberos Implementation. Default is false.
     *
     * @param debug true if debug should be enabled
     */
    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    /**
     * Kerberos config file location can be specified here.
     *
     * @param krbConfLocation the path to krb config file
     */
    public void setKrbConfLocation(String krbConfLocation) {
        this.krbConfLocation = krbConfLocation;
    }

}
