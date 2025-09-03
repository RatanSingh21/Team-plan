package in.teamPlan.secure_auth_api.util;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
// uses patterns and matcher for the same...
public class RegexUtil {

    public static final Pattern emailPattern = Pattern.compile("^[\\w.-]+@[\\w.-]+\\.\\w{2,4}$"); // first word then @ then word then dot(.) and word of length l  ( 2 < l< 4 )
    public static final Pattern phonePattern = Pattern.compile("^\\d{10}$"); //  number of 10 length
    public static final Pattern stringPattern = Pattern.compile("^[a-zA-Z\\s]{2,}$"); // alpha a-z and A-Z and minimum 2 alpha is required
    public static final Pattern numericPattern = Pattern.compile("^-?\\\\d+$"); // digits of any length

    public static boolean isValidEmail(String input){
        return emailPattern.matcher(input).matches();
    }

    public static boolean isValidPhone(String input){
        return phonePattern.matcher(input).matches();
    }

    public static boolean isValidString(String input) {
        return stringPattern.matcher(input).matches();
    }

    public static boolean isValidNumeric(String input){
        return !numericPattern.matcher(input).matches();
    }

    // for any custom regexValidations
    public static boolean matchesCustomRegex(String input, String regex) {
        return !Pattern.compile(regex).matcher(input).matches();
    }

}