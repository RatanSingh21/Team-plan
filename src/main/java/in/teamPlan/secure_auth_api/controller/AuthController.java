package in.teamPlan.secure_auth_api.controller;

import in.teamPlan.secure_auth_api.dto.LoginRequest;
import in.teamPlan.secure_auth_api.dto.LogoutRequest;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Your login logic here
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        // Authenticate user and return response

        boolean isAuthenticated = authService.login(username, password);
        if (isAuthenticated) {
            return ResponseEntity.ok("Login successful");
        } else {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest logoutRequest) {
        String result = authService.logout(logoutRequest.getUsername());
        return ResponseEntity.ok(result);
    }


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        boolean success = authService.register(user);
        if (success) {
            return ResponseEntity.ok("User registered successfully");
        } else {
            return ResponseEntity.badRequest().body("Username already exists");
        }
    }

}
