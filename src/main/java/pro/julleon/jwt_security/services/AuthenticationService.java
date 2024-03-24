package pro.julleon.jwt_security.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pro.julleon.jwt_security.controllers.auth.request.AuthenticationRequest;
import pro.julleon.jwt_security.controllers.auth.request.RegisterRequest;
import pro.julleon.jwt_security.controllers.auth.response.AuthenticationResponse;
import pro.julleon.jwt_security.repositories.UserRepository;
import pro.julleon.jwt_security.userdetails.Role;
import pro.julleon.jwt_security.userdetails.User;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        return AuthenticationResponse
                .builder()
                .jwt(jwtService.generateJwt(
                        userRepository.save(
                                User.builder()
                                        .firstName(registerRequest.getFirstName())
                                        .lastName(registerRequest.getLastName())
                                        .email(registerRequest.getEmail())
                                        .password(passwordEncoder.encode(registerRequest.getPassword()))
                                        .role(Role.USER)
                                        .build())
                ))
                .build();
    }

    @Transactional
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword())
        );
        User userDetails = userRepository.findByEmail(
                authenticationRequest.getEmail()).orElseThrow();
        String jwt = jwtService.generateJwt(userDetails);
        return AuthenticationResponse
                .builder()
                .jwt(jwt)
                .build();
    }
}
