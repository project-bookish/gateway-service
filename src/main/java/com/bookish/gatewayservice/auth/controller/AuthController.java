package com.bookish.gatewayservice.auth.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @PostMapping(
            path = "/authenticate",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public String login() {
        return "Not implemented";
    }

    @PostMapping(
            path = "/register",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void register() {

    }

    @PostMapping(
            path = "/logout",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public void logout() {

    }
}
