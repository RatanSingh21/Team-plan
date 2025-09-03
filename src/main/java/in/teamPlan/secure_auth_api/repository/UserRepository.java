package in.teamPlan.secure_auth_api.repository;

import in.teamPlan.secure_auth_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

    // You can add custom query methods here if needed
    Optional<User> findByUsername(String username);

}
