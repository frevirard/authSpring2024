package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.config.JwtService;
import com.example.demo.config.Utilisateur;

@RestController
@RequestMapping("/booms")
public class FredController {

    @Autowired
    AuthenticationProvider authenticationProvider;

    @Autowired
    JwtService jwtService;

    @GetMapping("/fred/{id}")
    public ResponseEntity<String> test(@PathVariable String id) {
        if (id.equals("4")) {
            try {
                Number fred = 4 / 0;
            } catch (Exception e) {
                // TODO: handle exception
                return new ResponseEntity<String>(e.toString(), HttpStatus.BAD_REQUEST);
            }

        } else {
            return new ResponseEntity<String>("fred", HttpStatus.OK);
        }
        return null;
    }

    @GetMapping("/wojak")
    public ResponseEntity<String> cooms() {
        return new ResponseEntity<>("Fred", HttpStatus.OK);
    }

    @PostMapping("/go")
    public String singIn(@RequestBody Utilisateur utilisateur) {
        Authentication authentication = this.authenticationProvider
                .authenticate(new UsernamePasswordAuthenticationToken(utilisateur.username, utilisateur.password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        if (authentication.isAuthenticated()) {
            return this.jwtService.generateJwtToken(authentication);
        }

        return "non authentifié";
    }

    @PostMapping("/doom")
    public String ok() {
        return "Dooms Day";
    }

}
