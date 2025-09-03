package in.teamPlan.secure_auth_api.repository;

import in.teamPlan.secure_auth_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {

    // You can add custom query methods here if needed
    User findByUsername(String username);


}
