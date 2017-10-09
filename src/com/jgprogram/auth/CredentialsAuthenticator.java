package com.jgprogram.auth;

/**
 * Credentials authenticator authenticate credentials
 *
 */
public interface CredentialsAuthenticator {
    /**
     * Authenticate credentials
     * 
     * @param username
     * @param password
     * @return True if credentials are authenticated
     */
    boolean authenticate(String username, String password);
}
