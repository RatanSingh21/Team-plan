package in.teamPlan.secure_auth_api.service;

import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        public boolean login(String username, String password) {
            User user = userRepository.findByUsername(username);
            if (user != null && passwordEncoder.matches(password, user.getPassword())) {
                // Generate and return token here (e.g., JWT)
                return true;
            }
            return false;
        }

        public String logout(String username) {
            // Implement token invalidation if using JWT or session management

            User user = userRepository.findByUsername(username);
            if (user != null) {
                return "Logout successful for user: " + username;
            }
            return "User not found";

        }
        public boolean register(User user) {
            if (userRepository.findByUsername(user.getUsername()) != null) {
                return false; // Username already exists
            }
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.save(user);
            return true;
        }
}

