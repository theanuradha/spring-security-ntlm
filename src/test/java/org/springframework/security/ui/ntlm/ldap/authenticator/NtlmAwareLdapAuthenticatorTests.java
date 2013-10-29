package org.springframework.security.ui.ntlm.ldap.authenticator;

import jcifs.smb.NtlmPasswordAuthentication;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;

/**
 * @author Luke Taylor
 * @author Alois Cochard
 * @author Edouard De Oliveira
 */
public class NtlmAwareLdapAuthenticatorTests {    
    
	private static final String USER_INFO="domain;user:password";
	private static LdapContextSource ctx;
	
	private static NtlmAwareLdapAuthenticator authenticator;
	
	@BeforeClass
	public static void init() throws Exception
	{
		// User used to connect and search through ldap
		ctx = new DefaultSpringSecurityContextSource("ldap://domainController:389/");
    	ctx.setUserDn("cn=ldapUser,cn=Users,dc=domain,dc=loc");
    	ctx.setPassword("******");
    	ctx.afterPropertiesSet();
	}
	
	@Before
	public void initTest()
	{
		authenticator = new NtlmAwareLdapAuthenticator(ctx);
		
		// add filter if necessary
        FilterBasedLdapUserSearch filter = new FilterBasedLdapUserSearch("dc=domain,dc=loc", "(sAMAccountName={0})", ctx);
        filter.setSearchSubtree(true);
        authenticator.setUserSearch(filter);
	}
	
	/**
     * See SEC-609.
     */
    @Test(expected = BadCredentialsException.class)
    public void unauthenticatedTokenIsRejected()
    {
        NtlmUsernamePasswordAuthenticationToken token = new NtlmUsernamePasswordAuthenticationToken(
                new NtlmPasswordAuthentication("domain;user:fakepwd"), false);
        token.setAuthenticated(false);

        authenticator.authenticate(token);
    }

    @Test
    public void authenticatedTokenIsAccepted() throws Exception {
        NtlmUsernamePasswordAuthenticationToken token = new NtlmUsernamePasswordAuthenticationToken(
                new NtlmPasswordAuthentication(USER_INFO), true);

        authenticator.authenticate(token);
    }
}
