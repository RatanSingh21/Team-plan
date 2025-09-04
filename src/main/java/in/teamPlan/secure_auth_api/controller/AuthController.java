package in.teamPlan.secure_auth_api.controller;
import java.util.List;
import in.teamPlan.secure_auth_api.dto.ErrorResponse;
import in.teamPlan.secure_auth_api.dto.LoginRequest;
import in.teamPlan.secure_auth_api.dto.LogoutRequest;
import in.teamPlan.secure_auth_api.dto.TokenResponse;
import in.teamPlan.secure_auth_api.util.exception.CustomException;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.service.AuthService;
import in.teamPlan.secure_auth_api.util.RegexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication Controller", description = "Endpoints for user authentication and management")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    private AuthService authService;


    @RateLimiter(name = "loginLimiter", fallbackMethod = "loginRateLimitFallback")
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {

        logger.info("[AuthController] Login attempt for username: {}", loginRequest.getUsername());
        // Validate username format
        if (!RegexUtil.isValidString(loginRequest.getUsername())) {
            logger.warn("[AuthController] Invalid username format: {}", loginRequest.getUsername());
            throw new CustomException("Username should contain only letters (a-z or A-Z)");
        }

        // Validate password format
        if (RegexUtil.matchesCustomRegex(loginRequest.getPassword(),
                "^(?=.*[0-9])(?=.*[!@%^&*()_+=<>?,./-])[a-zA-Z0-9!@%^&*()_+=<>?,./-]{6,24}$")) {
            logger.warn("[AuthController] Invalid password format for username: {}", loginRequest.getUsername());
            throw new CustomException("Password must be 6-24 characters long, contain at least one number and one special character (!@%^&*()_+=<>?,./-)");
        }

        TokenResponse response = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
        logger.info("[AuthController] Login successful for username: {}", loginRequest.getUsername());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    public ResponseEntity<ErrorResponse> loginRateLimitFallback(LoginRequest loginRequest, RequestNotPermitted ex) {
        String username = (loginRequest != null && loginRequest.getUsername() != null)
                ? loginRequest.getUsername()
                : "unknown";
        logger.warn("[AuthController] Login rate limit exceeded for username: {}", username);

        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase(),
                "You have exceeded the login rate limit. Please try again later.",
                "/auth/login" // Adjust this path as needed
        );

        return new ResponseEntity<>(errorResponse, HttpStatus.TOO_MANY_REQUESTS);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody LogoutRequest logoutRequest) {
        logger.info("[AuthController] Logout attempt for username: {}", logoutRequest.getUsername());
        if (!RegexUtil.isValidString(logoutRequest.getUsername())) {
            logger.warn("[AuthController] Invalid username format: {}", logoutRequest.getUsername());
            throw new CustomException("Invalid username format");
        }

        String result = authService.logout(logoutRequest.getUsername());
        logger.info("[AuthController] Logout successful for username: {}", logoutRequest.getUsername());
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        logger.info("[AuthController] Registration attempt for username: {}", user.getUsername());
        if (!RegexUtil.isValidString(user.getUsername())) {
            logger.warn("[AuthController] Invalid username format: {}", user.getUsername());
            throw new CustomException("Invalid username format");
        }

        if (RegexUtil.matchesCustomRegex(user.getPassword(),
                "^(?=.*[0-9])(?=.*[!@%^&*()_+=<>?,./-])[a-zA-Z0-9!@%^&*()_+=<>?,./-]{6,24}$")) {
            logger.warn("[AuthController] Invalid password format for username: {}", user.getUsername());
            throw new CustomException("Password must be 6-24 characters long, contain at least one number and one special character (!@%^&*()_+=<>?,./-)");
        }

        boolean success = authService.register(user);
        if (!success) {
            logger.warn("[AuthController] Registration failed, username already exists: {}", user.getUsername());
            throw new CustomException("Username already exists");
        }
        logger.info("[AuthController] Registration successful for username: {}", user.getUsername());
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestHeader("Authorization") String refreshToken) {
        logger.info("[AuthController] Refresh token attempt");
        refreshToken = refreshToken.replace("Bearer ", "");
        TokenResponse response = authService.refreshToken(refreshToken);
        logger.info("[AuthController] Token refreshed successfully");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    @GetMapping("/users")
    @RateLimiter(name = "getAllUsersLimiter", fallbackMethod = "getAllUsersRateLimitFallback")
    @CircuitBreaker(name = "getAllUsersCB", fallbackMethod = "getAllUsersCircuitBreakerFallback")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = authService.getAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }
    // Circuit breaker fallback
    public ResponseEntity<ErrorResponse> getAllUsersCircuitBreakerFallback(Throwable ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(),
                "Service is temporarily unavailable. Please try again later.",
                "/auth/users"
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.SERVICE_UNAVAILABLE);
    }

}