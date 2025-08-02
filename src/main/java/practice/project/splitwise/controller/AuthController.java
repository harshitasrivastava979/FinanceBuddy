package practice.project.splitwise.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import practice.project.splitwise.model.Users;
import practice.project.splitwise.repository.UserRepo;
import practice.project.splitwise.service.JwtUtil;
import practice.project.splitwise.dto.UserResponseDTO;
import practice.project.splitwise.dto.LoginResponseDTO;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepo userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Users user) {
        if (userRepo.findByMail(user.getMail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email already in use");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Users savedUser = userRepo.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.get("mail"),
                            loginRequest.get("password")
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtil.generateToken(authentication.getName());
            
            // Get user data
            Users user = userRepo.findByMail(loginRequest.get("mail"))
                    .orElseThrow(() -> new RuntimeException("User not found after authentication"));
            
            UserResponseDTO userData = new UserResponseDTO(user.getId(), user.getName(), user.getMail());
            
            LoginResponseDTO loginResponse = new LoginResponseDTO(jwt, userData);
            
            System.out.println("Login response: " + loginResponse); // Debug log
            return ResponseEntity.ok(loginResponse);
            
        } catch (Exception e) {
            System.err.println("Login error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Login failed: " + e.getMessage());
        }
    }
} 