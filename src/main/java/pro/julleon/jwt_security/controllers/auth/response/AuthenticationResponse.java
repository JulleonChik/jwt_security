package pro.julleon.jwt_security.controllers.auth.response;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String jwt;
}
