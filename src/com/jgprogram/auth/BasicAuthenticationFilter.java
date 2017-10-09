package com.jgprogram.auth;

import java.io.IOException;
import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import meritumit.drukarnia.raporty.facade.PracownicyFacade;
import com.jgprogram.auth.AuthenticationService;
import com.jgprogram.auth.CredentialsAuthenticator;

@WebFilter(
        filterName = "BasicAuthenticationFilter",
        description = "It checks that request to MyServlet is authenticated",
        urlPatterns = {"/my-servlet/*"},
        servletNames = {"MyServlet"}
)
public class BasicAuthenticationFilter implements Filter {

    @Inject
    private AuthenticationService authService;

    @Inject
    private MyFacade myFacade;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        boolean isAuth = authService.BasicAuthenticate(httpRequest, new CredentialsAuthenticator() {
            @Override
            public boolean authenticate(String username, String password) {
                return !myFacade.findByLoginPassword(username, password).isEmpty();
            }
        });

        if (isAuth) {
            chain.doFilter(request, response);
        } else {
            authService.AppendUnauthorizedToResponse(httpResponse, "my-servlet");
        }
    }

    @Override
    public void destroy() {

    }
}
