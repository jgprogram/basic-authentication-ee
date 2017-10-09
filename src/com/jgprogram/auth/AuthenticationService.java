package com.jgprogram.auth;

import java.io.IOException;
import java.util.Base64;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Stateless
public class AuthenticationService {

    /**
     * It looks for basic Authorization heder in request and authenticate it by {@see com.jgprogram.auth.CredentialsAuthenticator}.
     *
     * @param httpRequest
     * @param credentialsAuthenticator
     * @return Return true if credentials in request are authenticated.
     */
    public boolean basicAuthenticate(HttpServletRequest httpRequest, CredentialsAuthenticator credentialsAuthenticator) {
        String authHeader = httpRequest.getHeader("Authorization");

        return basicAuthenticate(authHeader, credentialsAuthenticator);
    }

    /**
     * It decodes authCredentials and authenticate it by {@see com.jgprogram.auth.CredentialsAuthenticator}.
     *
     * Credentials format: Basic Base64EncodedUserPasswordToken
     * UserPasswordToken: username:password
     *
     * @see <a href="https://tools.ietf.org/html/rfc2617#section-2">Documentation of basic http token</a>
     *
     * @param authCredentials
     * @param credentialsAuthenticator
     * @return Return true if credentials are authenticated.
     */
    public boolean basicAuthenticate(String authCredentials, CredentialsAuthenticator credentialsAuthenticator) {
        boolean isAuth = false;

        if (authCredentials != null && authCredentials.contains("Basic ")) {
            // Auth credentials format: "Basic YWRtaW46YWRtaW4="
            final String encodedUserPassword = authCredentials.replaceFirst("Basic ", "");

            try {
                byte[] decodeBytes = Base64.getDecoder().decode(encodedUserPassword);
                final String usernameAndPass = new String(decodeBytes, "UTF-8");

                //Token auth format: username:pass
                final StringTokenizer credentialsTokenizer = new StringTokenizer(usernameAndPass, ":");
                final String username = credentialsTokenizer.nextToken();
                final String pass = credentialsTokenizer.nextToken();

                isAuth = credentialsAuthenticator.authenticate(username, pass);
            } catch (Exception ex) {
                Logger.getLogger(AuthenticationService.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return isAuth;
    }

    /**
     * It appends unauthorized header and "401 Unauthorized" status code to
     * response
     *
     * @see <a href="https://tools.ietf.org/html/rfc2617#section-3.2.1">Documentation of basic http token</a>
     *
     * @param response - HttpServletResponse where append data.
     * @param realm - A string to be displayed to users so they know which
     * username and password to use. This string should contain at least the
     * name of the host performing the authentication and might additionally
     * indicate the collection of users who might have access. An example might
     * be "registered_users@gotham.news.com".
     *
     * @throws IOException If cannot send status code to response
     */
    public void AppendUnauthorizedToResponse(HttpServletResponse response, String realm) throws IOException {
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        response.sendError(401, "Unauthorized");
    }
}
