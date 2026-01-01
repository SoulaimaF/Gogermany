package tn.pfe.gogermany;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    public UserController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }


    // GET /users → list all users
    @GetMapping
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // GET /users/{id} → get user by ID
    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable String id) {
        Optional<User> user = userRepository.findById(id);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // GET /users/email?email=xxx → get user by email
    @GetMapping("/email")
    public ResponseEntity<User> getUserByEmail(@RequestParam String email) {
        Optional<User> user = userRepository.findByEmail(email.trim());
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {

        if (userRepository.existsByEmail(user.getEmail()))
            return ResponseEntity.badRequest().body("Email exists");

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // default role
        if (user.getRole() == null) user.setRole(Role.STUDENT);

        userRepository.save(user);

        return ResponseEntity.ok("Registered successfully");
    }

    // PUBLIC - login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {

        String email = body.get("email");
        String password = body.get("password");

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) return ResponseEntity.status(401).body("User not found");

        User user = userOpt.get();

        if (!passwordEncoder.matches(password, user.getPassword()))
            return ResponseEntity.status(401).body("Wrong password");

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole());

        return ResponseEntity.ok(Map.of(
                "token", token,
                "role", user.getRole(),
                "email", user.getEmail()
        ));
    }
    // DELETE /users/{id} → only ADMIN can delete users
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id,
                                        @RequestHeader("Authorization") String authHeader) {

        // Check for missing token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);

        // Validate token
        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(401).body("Invalid token");
        }

        // Extract email and role from token
        String email = jwtUtil.getEmailFromToken(token);
        String role = jwtUtil.extractClaims(token).get("role", String.class);

        // Only ADMIN can delete
        if (!"ADMIN".equals(role)) {
            return ResponseEntity.status(403).body("Only ADMIN can delete users");
        }

        // Prevent admin from deleting themselves
        Optional<User> targetUserOpt = userRepository.findById(id);
        if (targetUserOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User targetUser = targetUserOpt.get();
        if (targetUser.getEmail().equals(email)) {
            return ResponseEntity.status(403).body("Admin cannot delete their own account");
        }

        // Delete user
        userRepository.deleteById(id);
        return ResponseEntity.ok("User deleted successfully");
    }

}