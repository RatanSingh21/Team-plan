package in.teamPlan.secure_auth_api.service;

import in.teamPlan.secure_auth_api.dto.TokenResponse;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.repository.UserRepository;
import in.teamPlan.secure_auth_api.util.jwt.JwtUtil;
import in.teamPlan.secure_auth_api.util.exception.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public TokenResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new CustomException("Invalid credentials");
        }

        String accessToken = jwtUtil.generateAccessToken(username);
        String refreshToken = jwtUtil.generateRefreshToken(username);

        return new TokenResponse("Login successful", accessToken, refreshToken);
    }

    public TokenResponse refreshToken(String refreshToken) {
        if (!jwtUtil.validateToken(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
            throw new CustomException("Invalid refresh token");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        String newAccessToken = jwtUtil.generateAccessToken(username);

        return new TokenResponse("Token refreshed", newAccessToken, refreshToken);
    }

    public String logout(String username) {
        return userRepository.findByUsername(username)
                .map(user -> "Logout successful for user: " + username)
                .orElseThrow(() -> new CustomException("User not found"));
    }

    public boolean register(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return false;
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }
}