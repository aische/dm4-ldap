
##LDAP Authentication for DeepaMehta

####LDAP Settings (deepamehta/pom.xml)

- ######Normal LDAP protocol without encryption

        <dm4.ldap.protocol></dm4.ldap.protocol>
        <dm4.ldap.server>127.0.0.1</dm4.ldap.server>
        <dm4.ldap.port>389</dm4.ldap.port>
        <dm4.ldap.manager>admin</dm4.ldap.manager>
        <dm4.ldap.password>password</dm4.ldap.password>
        <dm4.ldap.user_base>ou=users,o=mojo</dm4.ldap.user_base>
        <dm4.ldap.user_attribute>uid</dm4.ldap.user_attribute>
        <dm4.ldap.filter>objectClass=inetOrgPerson</dm4.ldap.filter>

- ######StartTLS

        <dm4.ldap.protocol>StartTLS</dm4.ldap.protocol>
        <dm4.ldap.port>389</dm4.ldap.port>

- ######LDAPS/SSL

        <dm4.ldap.protocol>LDAPS</dm4.ldap.protocol>
        <dm4.ldap.port>636</dm4.ldap.port>

Known Protocols are: 

- StartTLS (ldap://HOST:389) - default port is 389
- LDAPS (ldaps://HOST:636) - default port is 636
- Any other value means "normal LDAP protocol without encryption" (ldap://HOST:389) - default port is 389

Additional settings for self-signed certificates used with keystore:

        <javax.net.ssl.trustStore>/path/to/keystore.jks</javax.net.ssl.trustStore>
        <javax.net.ssl.trustStorePassword>changeit</javax.net.ssl.trustStorePassword>

Note: For self signed certificates, dm4.ldap.server must contain the hostname of the certificate, not the IP address.


#### Changelog

**0.3.0** -- Feb 27, 2018

* Add StartTLS and LDAPS/SSL protocols

**0.2.0** -- Feb 4, 2018

* Creates only a DM Username topic (along with private workspace) on first successful LDAP login
* Requires DeepaMehta 4.9.1

**0.1.0** -- Nov 30, 2017

* Basic functionality
* Creates full DM User Account on first successful LDAP login
* Requires DeepaMehta 4.9
