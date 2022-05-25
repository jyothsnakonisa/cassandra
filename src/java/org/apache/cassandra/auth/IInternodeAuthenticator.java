/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cassandra.auth;

import java.net.InetAddress;
import java.security.cert.Certificate;

import org.apache.cassandra.exceptions.ConfigurationException;

public interface IInternodeAuthenticator
{
    /**
     * Decides whether or not a peer is allowed to connect to this node.
     * If this method returns false, the socket will be immediately closed.
     *
     * @param remoteAddress ip address of the connecting node.
     * @param remotePort port of the connecting node.
     * @return true if the connection should be accepted, false otherwise.
     */
    boolean authenticate(InetAddress remoteAddress, int remotePort);

    /**
     * Decides whether a peer is allowed to connect to this node.
     * If this method returns false, the socket will be immediately closed.
     *
     * @param certificates client certificates
     * @return true if the connection should be accepted, false otherwise.
     */
    default boolean authenticate(Certificate[] certificates)
    {
        return false;
    }


    /**
     * Decides whether a peer is allowed to connect to this node.
     * If this method returns false, the socket will be immediately closed.
     *
     * @param remoteAddress ip address of the connecting node.
     * @param remorePort port of the connecting node.
     * @param certificates client certificates
     * @return true if the connection should be accepted, false otherwise.
     */
    default boolean authenticate(InetAddress remoteAddress, int remorePort, Certificate[] certificates)
    {
        if (certificates != null)
        {
            return authenticate(certificates);
        }
        return authenticate(remoteAddress, remorePort);
    }

    /**
     * Validates configuration of IInternodeAuthenticator implementation (if configurable).
     *
     * @throws ConfigurationException when there is a configuration error.
     */
    void validateConfiguration() throws ConfigurationException;

    /**
     * Setup is called once upon system startup to initialize the IAuthenticator.
     *
     * For example, use this method to create any required keyspaces/column families.
     */
    default void setup()
    {

    }
}
