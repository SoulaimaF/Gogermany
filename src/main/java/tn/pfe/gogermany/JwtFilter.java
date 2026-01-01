package tn.pfe.gogermany;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtFilter(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        // Skip login, register, and DELETE
        if (path.startsWith("/users/login") || path.startsWith("/users/register") || "DELETE".equalsIgnoreCase(method)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Read token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Missing or invalid Authorization header");
            return;
        }

        String token = authHeader.substring(7);
        if (!jwtUtil.validateToken(token)) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid token");
            return;
        }

        // Extract role from token
        String role = jwtUtil.extractClaims(token).get("role", String.class);

        // Protect activate/deactivate → only ADMIN
        if ((path.endsWith("/activate") || path.endsWith("/deactivate")) && !"ADMIN".equals(role)) {
            response.sendError(HttpStatus.FORBIDDEN.value(), "Only ADMIN can change account status");
            return;
        }

        filterChain.doFilter(request, response);
    }
    
}