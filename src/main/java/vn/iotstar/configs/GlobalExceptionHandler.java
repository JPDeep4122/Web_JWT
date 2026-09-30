package vn.iotstar.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.proc.BadJWTException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.ParseException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetail = null;
        exception.printStackTrace();

        if (exception instanceof BadCredentialsException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), exception.getMessage());
            errorDetail.setProperty("description", "The username or password is incorrect");
            return errorDetail;
        }

        if (exception instanceof AccountStatusException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetail.setProperty("description", "The account is locked");
            return errorDetail;
        }

        if (exception instanceof AccessDeniedException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetail.setProperty("description", "You are not authorized to access this resource");
            return errorDetail;
        }

        // Handle Nimbus JOSE / JWT exceptions (BadJWTException, BadJOSEException, ParseException, etc.)
        Throwable cause = exception;
        while (cause != null) {
            if (cause instanceof BadJWTException || (cause.getMessage() != null && cause.getMessage().toLowerCase().contains("expired"))) {
                errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), "The JWT token has expired");
                errorDetail.setProperty("description", "The JWT token has expired");
                return errorDetail;
            }

            if (cause instanceof BadJOSEException || cause instanceof JOSEException || cause instanceof ParseException
                    || (cause.getMessage() != null && (cause.getMessage().toLowerCase().contains("signature") || cause.getMessage().toLowerCase().contains("jwt")))) {
                errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), "The JWT signature is invalid");
                errorDetail.setProperty("description", "The JWT signature is invalid");
                return errorDetail;
            }

            if (cause.getCause() == cause) {
                break;
            }
            cause = cause.getCause();
        }

        if (errorDetail == null) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(500), exception.getMessage());
            errorDetail.setProperty("description", "Unknown internal server error.");
        }

        return errorDetail;
    }
}
