/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2005-2014 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2014 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.netmgt.notifd;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;
import org.jivesoftware.smack.chat.Chat;
import org.jivesoftware.smack.chat.ChatManager;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.chat.ChatMessageListener;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.TLSUtils;
import org.jivesoftware.smackx.muc.MultiUserChat;
import org.jivesoftware.smackx.muc.MultiUserChatException.NotAMucServiceException;
import org.jivesoftware.smackx.muc.MultiUserChatManager;
import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.EntityJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Resourcepart;
import org.jxmpp.stringprep.XmppStringprepException;
import org.opennms.core.logging.Logging;
import org.opennms.core.utils.ConfigFileConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.geekplace.javapinning.java7.Java7Pinning;

/**
 * Singleton class used to send messages to an XMPP Server. Used by
 * XMPPNotificationStragetgy and XMPPGroupNotificationStrategy
 *
 * @author <a href="mailto:jonathan@opennms.org">Jonathan Sartin</a>
 * @author <a href="mailto:ranger@opennms.org">Benjamin Reed</a>
 * @version $Id: $
 */
public class XMPPNotificationManager {

    private static final Logger LOG = LoggerFactory.getLogger(XMPPNotificationManager.class);

	private final Properties props = new Properties();

	private static final String LOG4J_CATEGORY = "notifd";

	private static final String XMPP_PORT = "5222";

	private final XMPPTCPConnection xmpp;

	private final String xmppServer;

	private final String xmppUser;

	private final String xmppPassword;

	private final int xmppPort;

	private final Map<String, MultiUserChat> rooms = new HashMap<String, MultiUserChat>();

	private static XMPPNotificationManager instance = null;

	private ConnectionListener conlistener = new ConnectionListener() {
                @Override
		public void connectionClosed() {
			LOG.debug("XMPP connection closed");
		}

                @Override
		public void connectionClosedOnError(Exception e) {
			LOG.warn("XMPP connection closed", e);
		}

                @Override
        public void reconnectingIn(int seconds) {
            LOG.debug("XMPP reconnecting in {} seconds", seconds);
        }

                @Override
        public void reconnectionFailed(Exception e) {
            LOG.warn("XMPP reconnection failed", e);
             xmpp.disconnect();
            instance = null;
        }

                @Override
        public void reconnectionSuccessful() {
            LOG.debug("XMPP reconnection succeeded");
        }

        @Override
        public void authenticated(XMPPConnection conn, boolean resumed) {
            LOG.debug("XMPP authenticated resumed=" + resumed);
        }

        @Override
        public void connected(XMPPConnection conn) {
            LOG.debug("XMPP connected");
        }

	};

	/**
	 * <p>Constructor for XMPPNotificationManager.</p>
	 */
	protected XMPPNotificationManager() {
	    // mdc may be null when executing via unit tests
		Map<String,String> mdc = Logging.getCopyOfContextMap();
        try {
            if (mdc != null) {
                mdc.put(Logging.PREFIX_KEY, LOG4J_CATEGORY);
            }

			// Load up some properties
			File config = null;
			try {
				config = ConfigFileConstants.getFile(ConfigFileConstants.XMPP_CONFIG_FILE_NAME);
			} catch (IOException e) {
				LOG.warn("{} not readable", ConfigFileConstants.XMPP_CONFIG_FILE_NAME, e);
			}
			if (Boolean.getBoolean("useSystemXMPPConfig") || !config.canRead()) {
				this.props.putAll(System.getProperties());
			} else {
				FileInputStream fis = null;
				try {
					fis = new FileInputStream(config);
					this.props.load(fis);
				} catch (FileNotFoundException e) {
					LOG.warn("unable to load {}", config, e);
				} catch (IOException e) {
					LOG.warn("unable to load {}", config, e);
				} finally {
					IOUtils.closeQuietly(fis);
				}
			}

			xmppServer = this.props.getProperty("xmpp.server");
			String xmppServiceName = this.props.getProperty("xmpp.servicename", xmppServer);
			xmppUser = this.props.getProperty("xmpp.user");
			xmppPassword = this.props.getProperty("xmpp.pass");
			xmppPort = Integer.valueOf(this.props.getProperty("xmpp.port", XMPP_PORT));

			XMPPTCPConnectionConfiguration.Builder xmppConfig = XMPPTCPConnectionConfiguration.builder();

			DomainBareJid xmppDomain;
			try {
				xmppDomain = JidCreate.domainBareFrom(xmppServiceName);
			} catch (XmppStringprepException e) {
				throw new IllegalArgumentException(e);
			}
			xmppConfig.setHost(xmppServer).setPort(xmppPort).setXmppDomain(xmppDomain);

			boolean debuggerEnabled = Boolean.parseBoolean(props.getProperty("xmpp.debuggerEnabled"));
			xmppConfig.setDebuggerEnabled(debuggerEnabled);

			if (Boolean.parseBoolean(props.getProperty("xmpp.TLSEnabled"))) {
				xmppConfig.setSecurityMode(SecurityMode.required);
			} else {
				xmppConfig.setSecurityMode(SecurityMode.disabled);
			}

			String tlsCertPin = props.getProperty("xmpp.TLSCertPin");
			if (tlsCertPin != null && !tlsCertPin.isEmpty()) {
				SSLContext ctx;
				try {
					ctx = Java7Pinning.forPin(tlsCertPin);
				} catch (KeyManagementException | NoSuchAlgorithmException e) {
					throw new AssertionError(e);
				}
				xmppConfig.setCustomSSLContext(ctx);
			}
			// TODO Remove 'xmpp.selfSignedCertificateEnabled' in a future release since it is deprecated.
			else if (Boolean.parseBoolean(props.getProperty("xmpp.selfSignedCertificateEnabled"))) {
				try {
					TLSUtils.acceptAllCertificates(xmppConfig);
				} catch (KeyManagementException | NoSuchAlgorithmException e) {
					throw new AssertionError(e);
				}
			}

			XMPPTCPConnectionConfiguration buildXmppConfig = xmppConfig.build();
			LOG.debug("XMPP Manager connection config: {}", buildXmppConfig);

			xmpp = new XMPPTCPConnection(buildXmppConfig);

			// Connect to xmpp server
			connectToServer();
		} finally {
		    if (mdc != null) {
		        Logging.setContextMap(mdc);
		    }
		}
	}

	private void connectToServer() {
		try {
			LOG.debug("Attempting vanilla XMPP Connection to {}:{}", xmppServer, xmppPort);
			xmpp.connect();
			if (xmpp.isConnected()) {
				LOG.debug("XMPP Manager successfully connected");
				// Following requires a later version of the library
				if (xmpp.isSecureConnection()) 
					LOG.debug("XMPP Manager successfully negotiated a TLS secured connection");
				LOG.debug("XMPP Manager Connected"); 
				login();
				// Add connection listener
				xmpp.addConnectionListener(conlistener);
			} else {
				LOG.debug("XMPP Manager Not Connected");
			}
		} catch (Throwable e) {
			LOG.error("XMPP Manager unable to connect", e);
		}
	}

    /**
     * Check if manager is logged in to xmpp server.
     * 
     * @return true if logged in, false otherwise
     */

    private void login() {
        try {
            if (xmpp.isConnected()) {
                LOG.debug("XMPP Manager logging in");
                // Use 'null' as resourcepart argument and let the server assign a resource to us.
                xmpp.login(xmppUser, xmppPassword, null);
                rooms.clear();
            } else {
                LOG.debug("XMPP Manager unable to login: Not connected to XMPP server");
            }
        } catch (Throwable e) {
            LOG.error("XMPP Manager unable to login: ", e);
        }
    }

	/**
	 * get an instance of the XMPPNotificationManager
	 *
	 * @return instance of XMPPNotificationManager
	 */
	public static synchronized XMPPNotificationManager getInstance() {

		if (instance == null) {
			instance = new XMPPNotificationManager();
		}

		return instance;

	}

	/**
	 * <p>isLoggedIn</p>
	 *
	 * @return a boolean.
	 */
	public boolean isLoggedIn() {
		return (xmpp.isAuthenticated());
	}

	/**
	 * send an xmpp message to a specified recipient.
	 * 
	 * @param xmppTo
	 *            recipient of the xmpp message
	 * @param xmppMessage
	 *            text to be sent in the body of the message
	 * @return true if message is sent, false otherwise
	 */

	private static class NullMessageListener implements ChatMessageListener {
        @Override
        public void processMessage(Chat chat, Message message) {
        }
	}
	/**
	 * <p>sendMessage</p>
	 *
	 * @param xmppTo a {@link java.lang.String} object.
	 * @param xmppMessage a {@link java.lang.String} object.
	 * @return a boolean.
	 */
	public boolean sendMessage(String xmppTo, String xmppMessage) {
	    if (!isLoggedIn()) {
	        connectToServer();
	    }
		try {
		    EntityJid jid = JidCreate.entityBareFrom(xmppTo);
		    ChatManager cm = ChatManager.getInstanceFor(xmpp);
			cm.createChat(jid, new NullMessageListener()).sendMessage(xmppMessage);
			LOG.debug("XMPP Manager sent message to: {}", xmppTo);
		} catch (NotConnectedException | XmppStringprepException | InterruptedException e) {
			LOG.error("XMPP Exception Sending message ", e);
			return false;
		}

		return true;

	}

	/**
	 * send an xmpp message to a specified Chat Room.
	 *
	 * @param xmppChatRoom
	 *            room to send message to.
	 * @param xmppMessage
	 *            text to be sent in the body of the message
	 * @return true if message is sent, false otherwise
	 */
	public boolean sendGroupChat(String xmppChatRoom, String xmppMessage) {

		MultiUserChat groupChat;

		if (rooms.containsKey(xmppChatRoom)) {
			groupChat = rooms.get(xmppChatRoom);
		} else {
			LOG.debug("Adding room: {}", xmppChatRoom);
			MultiUserChatManager mucm = MultiUserChatManager.getInstanceFor(xmpp);
			try {
				groupChat = mucm.getMultiUserChat(JidCreate.entityBareFrom(xmppChatRoom));
			} catch (XmppStringprepException e) {
				LOG.error("XMPP Exception creating chat room ", e);
				return false;
			}
			rooms.put(xmppChatRoom, groupChat);
		}

		if (!groupChat.isJoined()) {
			LOG.debug("Joining room: {}", xmppChatRoom);
			try {
				groupChat.join(Resourcepart.from(xmppUser));
			} catch (XMPPException | NoResponseException | NotConnectedException | NotAMucServiceException | XmppStringprepException | InterruptedException e) {
				LOG.error("XMPP Exception joining chat room ", e);
				return false;
			}
		}

		try {
			groupChat.sendMessage(xmppMessage);
			LOG.debug("XMPP Manager sent message to: {}", xmppChatRoom);
		} catch (NotConnectedException | InterruptedException e) {
			LOG.error("XMPP Exception sending message to Chat room", e);
			return false;
		}

		return true;
	}

}
