package pro.julleon.jwt_security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pro.julleon.jwt_security.userdetails.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
}
