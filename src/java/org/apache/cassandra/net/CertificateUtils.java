/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.net;

import java.security.cert.Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;

/**
 * Class that contains certificate utility methods.
 */
class CertificateUtils
{
    public static String SSL_HANDLER_NAME = "ssl";
    public static String AUTHENTICATION_HANDLER_NAME = "authentication";
    public static String LOGGER_HANDLER_NAME = "logger";
    public static String HANDSHAKE_HANDLER_NAME = "handshake";
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

    public static Certificate[] certificates(Channel channel)
    {
        final SslHandler sslHandler = (SslHandler) channel.pipeline().get(SSL_HANDLER_NAME);
        Certificate[] certificates = null;
        if (sslHandler != null)
        {
            try
            {
                certificates = sslHandler.engine()
                                         .getSession()
                                         .getPeerCertificates();
            }
            catch (SSLPeerUnverifiedException e)
            {
                logger.debug("Failed to get peer certificates for peer {}", channel.remoteAddress(), e);
            }
        }
        return certificates;
    }

    public static void removeHandlersAndCloseTheChannel(ChannelHandlerContext channelHandlerContext) {
        final List<String> handlerNames = channelHandlerContext.pipeline().names();
        try {
            channelHandlerContext.pipeline().remove(AUTHENTICATION_HANDLER_NAME);
            channelHandlerContext.pipeline().remove(HANDSHAKE_HANDLER_NAME);
        } finally
        {
            channelHandlerContext.pipeline().close();
        }

//        final int authHandlerIndex = handlerNames.indexOf(AUTHENTICATION_HANDLER_NAME);
//        final List<String> handlersToBeRemoved = handlerNames.subList(authHandlerIndex, handlerNames.size()-1);
//        for(final String handler: handlersToBeRemoved) {
//            channelHandlerContext.pipeline().remove(handler);
//        }
//        channelHandlerContext.channel().close();

    }
}
