/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2021 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.hijacksession;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestHeader; // Added for CSRF token validation
import java.security.SecureRandom;
import java.util.Base64;

/***
 *
 * author Angel Olle Blazquez
 *
 */

@RestController
@AssignmentHints({
  "hijacksession.hints.1",
  "hijacksession.hints.2",
  "hijacksession.hints.3",
  "hijacksession.hints.4",
  "hijacksession.hints.5"
})
public class HijackSessionAssignment extends AssignmentEndpoint {

  private static final String COOKIE_NAME = "hijack_cookie";
  private static final String CSRF_TOKEN_HEADER = "X-CSRF-TOKEN";
  private static final String CSRF_COOKIE_NAME = "csrf_token";

  @Autowired HijackSessionAuthenticationProvider provider;

  @PostMapping(path = "/HijackSession/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      @RequestHeader(CSRF_TOKEN_HEADER) String csrfToken, // Added CSRF token
      @CookieValue(value = CSRF_COOKIE_NAME, required = false) String csrfCookie, // CSRF cookie validation
      HttpServletResponse response) {

    if (csrfToken == null || csrfCookie == null || !csrfToken.equals(csrfCookie)) {
      return failed(this).message("CSRF token mismatch").build();
    }

    Authentication authentication;
    if (StringUtils.isEmpty(cookieValue)) {
      authentication =
          provider.authenticate(
              Authentication.builder().name(username).credentials(password).build());
      setCookie(response, authentication.getId());
      setCsrfToken(response); // Set CSRF token on successful login
    } else {
      authentication = provider.authenticate(Authentication.builder().id(cookieValue).build());
      // CSRF token already validated above
    }

    if (authentication.isAuthenticated()) {
      return success(this).build();
    }

    return failed(this).build();
  }

  private void setCookie(HttpServletResponse response, String cookieValue) {
    Cookie cookie = new Cookie(COOKIE_NAME, cookieValue);
    cookie.setPath("/WebGoat");
    cookie.setSecure(true);
    cookie.setHttpOnly(true); // Setting HttpOnly flag
    response.addCookie(cookie);
  }

  private void setCsrfToken(HttpServletResponse response) {
    SecureRandom secureRandom = new SecureRandom();
    byte[] tokenBytes = new byte[32];
    secureRandom.nextBytes(tokenBytes);
    String csrfToken = Base64.getEncoder().encodeToString(tokenBytes);

    Cookie csrfCookie = new Cookie(CSRF_COOKIE_NAME, csrfToken);
    csrfCookie.setPath("/WebGoat");
    csrfCookie.setSecure(true);
    csrfCookie.setHttpOnly(true);
    response.addCookie(csrfCookie);
  }
}
