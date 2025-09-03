package in.teamPlan.secure_auth_api.controller;

import in.teamPlan.secure_auth_api.dto.LoginRequest;
import in.teamPlan.secure_auth_api.dto.LogoutRequest;
import in.teamPlan.secure_auth_api.dto.TokenResponse;
import in.teamPlan.secure_auth_api.util.exception.CustomException;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.service.AuthService;
import in.teamPlan.secure_auth_api.util.RegexUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
        // Validate username format
        if (!RegexUtil.isValidString(loginRequest.getUsername())) {
            throw new CustomException("Username should contain only letters (a-z or A-Z)");
        }

        // Validate password format
        if (RegexUtil.matchesCustomRegex(loginRequest.getPassword(),
                "^(?=.*[0-9])(?=.*[!@%^&*()_+=<>?,./-])[a-zA-Z0-9!@%^&*()_+=<>?,./-]{6,24}$")) {
            throw new CustomException("Password must be 6-24 characters long, contain at least one number and one special character (!@%^&*()_+=<>?,./-)");
        }

        TokenResponse response = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody LogoutRequest logoutRequest) {
        if (!RegexUtil.isValidString(logoutRequest.getUsername())) {
            throw new CustomException("Invalid username format");
        }

        String result = authService.logout(logoutRequest.getUsername());
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        if (!RegexUtil.isValidString(user.getUsername())) {
            throw new CustomException("Invalid username format");
        }

        if (RegexUtil.matchesCustomRegex(user.getPassword(),
                "^(?=.*[0-9])(?=.*[!@%^&*()_+=<>?,./-])[a-zA-Z0-9!@%^&*()_+=<>?,./-]{6,24}$")) {
            throw new CustomException("Password must be 6-24 characters long, contain at least one number and one special character (!@%^&*()_+=<>?,./-)");
        }

        boolean success = authService.register(user);
        if (!success) {
            throw new CustomException("Username already exists");
        }
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestHeader("Authorization") String refreshToken) {
        refreshToken = refreshToken.replace("Bearer ", "");
        TokenResponse response = authService.refreshToken(refreshToken);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}