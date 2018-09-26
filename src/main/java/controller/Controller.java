package controller;

import base64.*;
import client.SpnegoClient;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.util.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pac.Pac;
import pac.PacLogonInfo;
import pac.PacSid;
import spnego.Kerb4JException;
import spnego.SpnegoInitToken;
import spnego.SpnegoKerberosMechToken;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
public class Controller {

    @RequestMapping(value = "/test", method = RequestMethod.GET)
    public ResponseEntity<String> test(@RequestParam String token) {
        try{
            SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab("svc_consumer", "/opt/myapp/consumer.keytab");
            String negotiateHeaderValue = token.substring(10);
            byte[] decoded = Base64.decodeBase64(negotiateHeaderValue);
            SpnegoInitToken spnegoInitToken = new SpnegoInitToken(decoded);
            SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();
            Pac pac = spnegoKerberosMechToken.getPac(spnegoClient.getKerberosKeys());
            PacLogonInfo logonInfo = pac.getLogonInfo();
            String username = logonInfo.getUserName();
            List<String> roles = Stream.of(logonInfo.getGroupSids()).map(PacSid::toHumanReadableString).collect(Collectors.toList());
            String response = "Username: " + username + "; Roles: " + String.join(";", roles);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Arrays.toString(e.getStackTrace()), HttpStatus.OK);
        }
    }
}
