package pro.julleon.jwt_security.controllers.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pro.julleon.jwt_security.controllers.auth.request.AuthenticationRequest;
import pro.julleon.jwt_security.controllers.auth.response.AuthenticationResponse;
import pro.julleon.jwt_security.controllers.auth.request.RegisterRequest;
import pro.julleon.jwt_security.services.AuthenticationService;

@RestController
@RequestMapping("/api/v1/reception")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest registerRequest
    ) {
       return ResponseEntity
               .ok(authenticationService.register(registerRequest));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest authenticationRequest
    ) {
        return ResponseEntity
                .ok(authenticationService.authenticate(authenticationRequest));
    }
}