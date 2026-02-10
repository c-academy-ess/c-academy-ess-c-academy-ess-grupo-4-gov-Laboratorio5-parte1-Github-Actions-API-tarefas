package cncs.academy.ess.controller;

import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HandlerType;
import io.javalin.http.UnauthorizedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthorizationMiddleware implements Handler {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationMiddleware.class);
    private final UserRepository userRepository;

    public AuthorizationMiddleware(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        // if method is OPTIONS bypass auth middleware
        if (ctx.method() == HandlerType.OPTIONS) {
            // Optionally: validate if it is a legitimate CORS preflight
            return;
        }

        // Allow unauthenticated requests to /user (register) and /login
        if (ctx.path().equals("/user") && ctx.method().name().equals("POST") ||
                ctx.path().equals("/login") && ctx.method().name().equals("POST"))
            return;

        // Check if authorization header exists
        String authorizationHeader = ctx.header("Authorization");
        String path = ctx.path();
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.info("Authorization header is missing or invalid '{}' for path '{}'", authorizationHeader, path);
            throw new UnauthorizedResponse();
        }

        // Extract token from authorization header
        String token = authorizationHeader.substring(7); // Remove "Bearer "

        // Check if token is valid (perform authentication logic)
        int userId = validateTokenAndGetUserId(token);
        if (userId == -1) {
            logger.info("Authorization token is invalid {}", token  );
            throw new UnauthorizedResponse();
        }

        // Add user ID to context for use in route handlers
        ctx.attribute("userId", userId);
    }

    /**
     * NOTE: This method currently uses username lookup as a placeholder for real token validation.
     * Replace with proper token parsing/verification (e.g., JWT, session lookup) as needed.
     */
    private Integer validateTokenAndGetUserId(String token) {
        // Placeholder behavior: treat token as username (legacy behavior)
        User user = userRepository.findByUsername(token);
        if (user == null) {
            return -1;
        }
        return user.getId();
    }
}

