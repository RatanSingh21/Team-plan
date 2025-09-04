package in.teamPlan.secure_auth_api.service;
import java.util.Base64;
import in.teamPlan.secure_auth_api.dto.TokenResponse;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.repository.UserRepository;
import in.teamPlan.secure_auth_api.util.jwt.JwtUtil;
import in.teamPlan.secure_auth_api.util.exception.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import in.teamPlan.secure_auth_api.dto.UserSummaryDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.util.List;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public List<UserSummaryDto> getAllUserSummaries() {
        List<User> users = getAllUsers();
        return users.stream()
                .map(u -> new UserSummaryDto(u.getName(), u.getUsername(), u.getEmail()))
                .toList();
    }

    public TokenResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new CustomException("Invalid credentials");
        }

        String accessToken = jwtUtil.generateAccessToken(username);
        System.out.println("from auth service/login" + accessToken);
        String refreshToken = jwtUtil.generateRefreshToken(username);
        System.out.println("from auth service/login" + refreshToken);

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

    public void validateAndDecodeToken(String token) {
        try {
            // Check for null or empty token first
            if (token == null || token.trim().isEmpty()) {
                System.out.println("Token is null or empty");
                throw new CustomException("Token is missing or empty");
            }

            System.out.println("Validating token: " + token.substring(0, Math.min(token.length(), 20)) + "...");

            // First validate the token structure and expiry
            if (!jwtUtil.validateToken(token)) {
                System.out.println("Token validation failed in JwtUtil.validateToken()");
                throw new CustomException("Invalid or expired token");
            }

            // Check if it's an access token
            if (!jwtUtil.isAccessToken(token)) {
                System.out.println("Token is not an access token");
                throw new CustomException("Invalid token type - expected ACCESS token");
            }

            // Extract username to confirm token is readable
            String username = jwtUtil.extractUsername(token);
            System.out.println("Token validated successfully for user: " + username);

        } catch (CustomException ex) {
            // Re-throw custom exceptions as-is
            System.out.println("Custom validation error: " + ex.getMessage());
            throw ex;
        } catch (JwtException ex) {
            // Handle JWT-specific errors
            System.out.println("JWT parsing error: " + ex.getMessage());
            throw new CustomException("Invalid JWT token format");
        } catch (Exception ex) {
            // Handle any other unexpected errors
            System.out.println("Unexpected validation error: " + ex.getMessage());
            ex.printStackTrace(); // This will help debug the actual issue
            throw new CustomException("Token validation failed");
        }
    }
}