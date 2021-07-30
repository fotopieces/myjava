package com.scb.protec.controller;

import io.swagger.annotations.Api;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/v1/protected")
public class ProtectedController {

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ResponseEntity<String> getSomeSensitiveData(HttpServletRequest request, @RequestHeader(value = "username") String username) {
        String data = ">>>>>>>>>> :" + username;

        return new ResponseEntity<>(data, HttpStatus.OK);
    }
}
