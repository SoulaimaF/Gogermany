package tn.pfe.gogermany;

import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {

    // Find a user by email
    Optional<User> findByEmail(String email);
    // Check if a user exists by email
    boolean existsByEmail(String email);
}
