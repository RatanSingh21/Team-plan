package in.teamPlan.secure_auth_api.dto;

public class LogoutRequest {
    private String username;

    public LogoutRequest() {}

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
