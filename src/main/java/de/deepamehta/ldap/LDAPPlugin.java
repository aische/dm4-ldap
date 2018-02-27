package de.deepamehta.ldap;


import de.deepamehta.accesscontrol.AuthorizationMethod;
import de.deepamehta.accesscontrol.AccessControlService;

import de.deepamehta.core.service.accesscontrol.AccessControl;
import de.deepamehta.core.service.accesscontrol.Credentials;
import de.deepamehta.core.service.CoreService;
import de.deepamehta.core.storage.spi.DeepaMehtaTransaction;
import de.deepamehta.core.model.SimpleValue;
import de.deepamehta.core.model.TopicModel;
import de.deepamehta.core.osgi.PluginActivator;
import de.deepamehta.core.service.Inject;
import de.deepamehta.core.Topic;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.StartTlsResponse;
import javax.naming.ldap.StartTlsRequest;
import javax.net.ssl.SSLSession;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Hashtable;
import java.util.concurrent.Callable;


public class LDAPPlugin extends PluginActivator implements AuthorizationMethod {

    private Logger logger = Logger.getLogger(getClass().getName());
    private static final String LDAP_SERVER = System.getProperty("dm4.ldap.server", "127.0.0.1");
    private static final String LDAP_PORT = System.getProperty("dm4.ldap.port");
    private static final String LDAP_MANAGER = System.getProperty("dm4.ldap.manager", "");
    private static final String LDAP_PASSWORD = System.getProperty("dm4.ldap.password", "");
    private static final String LDAP_USER_BASE = System.getProperty("dm4.ldap.user_base", "");
    private static final String LDAP_USER_ATTRIBUTE = System.getProperty("dm4.ldap.user_attribute", "");
    private static final String LDAP_FILTER = System.getProperty("dm4.ldap.filter", "");
    private static final String LDAP_PROTOCOL = System.getProperty("dm4.ldap.protocol", "");

    // ---------------------------------------------------------------------------------------------- Instance Variables

    @Inject
    private AccessControlService acs;



    // ****************************
    // *** Hook Implementations ***
    // ****************************



    @Override
    public void serviceArrived(Object service) {
        ((AccessControlService) service).registerAuthorizationMethod("LDAP", this);
    }

    @Override
    public void serviceGone(Object service) {
        ((AccessControlService) service).unregisterAuthorizationMethod("LDAP");
    }



    // ******************************************
    // *** AuthorizationMethod implementation ***
    // ******************************************



    @Override
    public Topic checkCredentials(Credentials cred) {
        if (checkLdapCredentials(cred.username, cred.plaintextPassword)) {
            logger.info("LDAP login: OK");
            Topic usernameTopic = acs.getUsernameTopic(cred.username);
            if (usernameTopic != null) {
                return usernameTopic;
            } else {
                return createUsername(cred.username);
            }
        } else {
            return null;
        }
    }

    // ------------------------------------------------------------------------------------------------- Private Methods

    private Topic createUsername(String username) {
        DeepaMehtaTransaction tx = dm4.beginTx();
        try {
            Topic usernameTopic = acs.createUsername(username);
            tx.success();
            return usernameTopic;
        } catch (Exception e) {
            logger.warning("ROLLBACK! (" + this + ")");
            throw new RuntimeException("Creating username failed", e);
        } finally {
            tx.finish();
        }
    }

    private boolean checkLdapCredentials(String username, String password) {
        try {
            final String port = (LDAP_PORT == null) ? (LDAP_PROTOCOL.equals("LDAPS") ? "636" : "389") : LDAP_PORT;
            final String protocol = LDAP_PROTOCOL.equals("LDAPS") ? "ldaps://" : "ldap://";
            final String server = protocol + LDAP_SERVER + ":" + port;
            LdapContext ctx = connect(server, LDAP_MANAGER, LDAP_PASSWORD);
            String cn = lookupUserCn(ctx, LDAP_USER_BASE, username);
            if (cn == null) {
                return false;
            }
            LdapContext ctx2 = connect(server, cn, password);
            return ctx2 != null;
        } catch (Exception e) {
            throw new RuntimeException("Checking LDAP credentials failed", e);
        }
    }

    private LdapContext connect(String server, String username, String password) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, server);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        //ensures that objectSID attribute values
        //will be returned as a byte[] instead of a String
        env.put("java.naming.ldap.attributes.binary", "objectSID");
        
        // the following is helpful in debugging errors
        // env.put("com.sun.jndi.ldap.trace.ber", System.err);
        Control[] arr = new Control[0];
        LdapContext ctx = new InitialLdapContext(env, arr);
        if (LDAP_PROTOCOL.equals("StartTLS")) {
            try {
                StartTlsResponse tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
                SSLSession session = tls.negotiate();
            } catch (Exception e) {
                throw new RuntimeException("Could not establish TLS connection: " + e.toString());
            }
        }
        return ctx;
    }

    private static String lookupUserCn (LdapContext ctx, String ldapSearchBase, String uid) throws NamingException {
        String searchFilter = LDAP_FILTER.equals("")
                            ? "(" + LDAP_USER_ATTRIBUTE + "=" + uid + ")" 
                            : "(&(" + LDAP_FILTER + ")(" + LDAP_USER_ATTRIBUTE + "=" + uid + "))";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(ldapSearchBase, searchFilter, searchControls);
        if(results.hasMoreElements()) {
            SearchResult searchResult = (SearchResult) results.nextElement();
            if(results.hasMoreElements()) {
                throw new RuntimeException("Ambiguity in LDAP CN query: Matched multiple users for the accountName");
            }
            return searchResult.getNameInNamespace();
        } else {
            return null;
        }
    }
}
