package in.teamPlan.secure_auth_api.controller;

import in.teamPlan.secure_auth_api.dto.*;
import in.teamPlan.secure_auth_api.model.User;
import in.teamPlan.secure_auth_api.service.AuthService;
import in.teamPlan.secure_auth_api.util.RegexUtil;
import in.teamPlan.secure_auth_api.util.exception.CustomException;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Login Successful")
    void testLoginSuccess() {
        LoginRequest request = new LoginRequest("testuser", "Test@123");
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("test-token");
        tokenResponse.setRefreshToken("refresh-token");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("Test@123"), anyString())).thenReturn(false);

            when(authService.login("testuser", "Test@123")).thenReturn(tokenResponse);

            ResponseEntity<TokenResponse> response = authController.login(request);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals("test-token", response.getBody().getAccessToken());
        }
    }

    @Test
    @DisplayName("Invalid Username Check")
    void testLoginInvalidUsername() {
        LoginRequest request = new LoginRequest("invalid user!", "Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("invalid user!")).thenReturn(false);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.login(request));
            assertEquals("Username should contain only letters (a-z or A-Z)", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Invalid Password Check")
    void testLoginInvalidPassword() {
        LoginRequest request = new LoginRequest("testuser", "weak");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("weak"), anyString())).thenReturn(true);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.login(request));
            assertTrue(exception.getMessage().contains("Password must be 6-24 characters long"));
        }
    }

    @Test
    @DisplayName("Login Exception Check")
    void testLoginServiceException() {
        LoginRequest request = new LoginRequest("testuser", "Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("Test@123"), anyString())).thenReturn(false);

            when(authService.login("testuser", "Test@123")).thenThrow(new CustomException("Invalid credentials"));

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.login(request));
            assertEquals("Invalid credentials", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Rate Limiter Check")
    void testLoginRateLimitFallback() {
        LoginRequest request = new LoginRequest("testuser", "Test@123");
        RequestNotPermitted rateLimitException = mock(RequestNotPermitted.class);

        ResponseEntity<ErrorResponse> response = authController.loginRateLimitFallback(request, rateLimitException);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals(429, response.getBody().getStatus());
        assertTrue(response.getBody().getMessage().contains("rate limit"));
    }

    @Test
    @DisplayName("Check For Rate Limiter With Null Request")
    void testLoginRateLimitFallbackNullRequest() {
        RequestNotPermitted rateLimitException = mock(RequestNotPermitted.class);

        ResponseEntity<ErrorResponse> response = authController.loginRateLimitFallback(null, rateLimitException);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
    }

    @Test
    @DisplayName("Logout Successful")
    void testLogoutSuccess() {
        LogoutRequest request = new LogoutRequest("testuser");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            when(authService.logout("testuser")).thenReturn("Logged out successfully");

            ResponseEntity<String> response = authController.logout(request);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals("Logged out successfully", response.getBody());
        }
    }

    @Test
    @DisplayName("Invalid User Logout Check")
    void testLogoutInvalidUsername() {
        LogoutRequest request = new LogoutRequest("invalid user!");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("invalid user!")).thenReturn(false);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.logout(request));
            assertEquals("Invalid username format", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Logout Exception Check")
    void testLogoutServiceException() {
        LogoutRequest request = new LogoutRequest("testuser");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            when(authService.logout("testuser")).thenThrow(new CustomException("User not found"));

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.logout(request));
            assertEquals("User not found", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Register Successful")
    void testRegisterSuccess() {
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("Test@123"), anyString())).thenReturn(false);
            when(authService.register(user)).thenReturn(true);

            ResponseEntity<String> response = authController.register(user);

            assertEquals(HttpStatus.CREATED, response.getStatusCode());
            assertEquals("User registered successfully", response.getBody());
        }
    }

    @Test
    @DisplayName("Register With Invalid Username")
    void testRegisterInvalidUsername() {
        User user = new User();
        user.setUsername("invalid user!");
        user.setPassword("Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("invalid user!")).thenReturn(false);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.register(user));
            assertEquals("Invalid username format", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Register With Invalid Password")
    void testRegisterInvalidPassword() {
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("weak");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("weak"), anyString())).thenReturn(true);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.register(user));
            assertTrue(exception.getMessage().contains("Password must be 6-24 characters long"));
        }
    }

    @Test
    @DisplayName("Register Username Already Exists Check")
    void testRegisterUsernameAlreadyExists() {
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("Test@123"), anyString())).thenReturn(false);
            when(authService.register(user)).thenReturn(false);

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.register(user));
            assertEquals("Username already exists", exception.getMessage());
        }
    }

    @Test
    @DisplayName("Register Exception Check")
    void testRegisterServiceException() {
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("Test@123");

        try (MockedStatic<RegexUtil> mockedRegex = mockStatic(RegexUtil.class)) {
            mockedRegex.when(() -> RegexUtil.isValidString("testuser")).thenReturn(true);
            mockedRegex.when(() -> RegexUtil.matchesCustomRegex(eq("Test@123"), anyString())).thenReturn(false);
            when(authService.register(user)).thenThrow(new CustomException("Database error"));

            CustomException exception = assertThrows(CustomException.class,
                    () -> authController.register(user));
            assertEquals("Database error", exception.getMessage());
        }
    }


    @Test
    @DisplayName("Token Verification Successful")
    void testVerifyTokenSuccess() {
        String token = "valid-token";
        List<UserSummaryDto> users = Arrays.asList(
                new UserSummaryDto("user1", "Shivammm", "email1@test.com"),
                new UserSummaryDto("user2", "Reubendz", "email2@test.com")
        );

        doNothing().when(authService).validateAndDecodeToken(token);
        when(authService.getAllUserSummaries()).thenReturn(users);

        ResponseEntity<?> response = authController.validateTokenAndFetchUsers(token);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(users, response.getBody());
    }

    @Test
    @DisplayName("Null Token Verification Check")
    void testVerifyTokenNull() {
        ResponseEntity<?> response = authController.validateTokenAndFetchUsers(null);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorResponse errorResponse = (ErrorResponse) response.getBody();
        assertEquals(401, errorResponse.getStatus());
        assertEquals("Missing or invalid token", errorResponse.getMessage());
    }

    @Test
    @DisplayName("Empty Token Verification Check")
    void testVerifyTokenEmpty() {
        ResponseEntity<?> response = authController.validateTokenAndFetchUsers("");

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorResponse errorResponse = (ErrorResponse) response.getBody();
        assertEquals(401, errorResponse.getStatus());
        assertEquals("Missing or invalid token", errorResponse.getMessage());
    }

    @Test
    @DisplayName("Whitespace Present In Token")
    void testVerifyTokenWhitespace() {
        ResponseEntity<?> response = authController.validateTokenAndFetchUsers("   ");

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorResponse errorResponse = (ErrorResponse) response.getBody();
        assertEquals(401, errorResponse.getStatus());
        assertEquals("Missing or invalid token", errorResponse.getMessage());
    }

    @Test
    @DisplayName("Invalid Token Check")
    void testVerifyTokenInvalid() {
        String token = "invalid-token";

        doThrow(new CustomException("Invalid token")).when(authService).validateAndDecodeToken(token);

        ResponseEntity<?> response = authController.validateTokenAndFetchUsers(token);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorResponse errorResponse = (ErrorResponse) response.getBody();
        assertEquals(401, errorResponse.getStatus());
        assertEquals("Invalid token", errorResponse.getMessage());
    }

    @Test
    @DisplayName("Verify Token Exception ")
    void testVerifyTokenUnexpectedException() {
        String token = "valid-token";

        doThrow(new RuntimeException("Database connection failed")).when(authService).validateAndDecodeToken(token);

        ResponseEntity<?> response = authController.validateTokenAndFetchUsers(token);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrorResponse errorResponse = (ErrorResponse) response.getBody();
        assertEquals(500, errorResponse.getStatus());
        assertEquals("Something went wrong on the server", errorResponse.getMessage());
    }

    @Test
    @DisplayName("Refresh Token Successful")
    void testRefreshTokenSuccess() {
        String refreshToken = "Bearer refresh-token";
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("new-access-token");
        tokenResponse.setRefreshToken("new-refresh-token");

        when(authService.refreshToken("refresh-token")).thenReturn(tokenResponse);

        ResponseEntity<TokenResponse> response = authController.refreshToken(refreshToken);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("new-access-token", response.getBody().getAccessToken());
    }


    @Test
    @DisplayName("Refresh Token Exception Check")
    void testRefreshTokenServiceException() {
        String refreshToken = "Bearer invalid-refresh-token";

        when(authService.refreshToken("invalid-refresh-token")).thenThrow(new CustomException("Invalid refresh token"));

        CustomException exception = assertThrows(CustomException.class,
                () -> authController.refreshToken(refreshToken));
        assertEquals("Invalid refresh token", exception.getMessage());
    }
}


//    @Test
//    void testLoginNullRequest() {
//        assertThrows(NullPointerException.class, () -> authController.login(null));
//    }
//
//    @Test
//    void testLogoutNullRequest() {
//        assertThrows(NullPointerException.class, () -> authController.logout(null));
//    }
//
//    @Test
//    void testRegisterNullUser() {
//        assertThrows(NullPointerException.class, () -> authController.register(null));
//    }
//
//    @Test
//    void testRefreshTokenNull() {
//        assertThrows(NullPointerException.class, () -> authController.refreshToken(null));
//    }
//}