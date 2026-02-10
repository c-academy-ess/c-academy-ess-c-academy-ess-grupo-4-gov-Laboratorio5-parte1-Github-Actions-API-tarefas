package cncs.academy.ess.service;


import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import cncs.academy.ess.service.security.PasswordUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.security.NoSuchAlgorithmException;
import java.util.Date;

import static cncs.academy.ess.service.security.PasswordUtils.hashPassword;

public class TodoUserService {
    private final UserRepository repository;

    public TodoUserService(UserRepository userRepository) {
        this.repository = userRepository;
    }

    /**
     * Adds a new user if the username does not already exist.
     * Synchronized to reduce duplicate creation race conditions in-memory.
     * Throws DuplicateUserException when username is already taken.
     */
    public User addUser(String username, String password) throws NoSuchAlgorithmException, DuplicateUserException {
       if (repository.findByUsername(username) != null) {
           throw new DuplicateUserException("Username already exists: " + username);
       }

       String passwordHash = hashPassword(password);

       User user = new User(username, passwordHash);
       int id = repository.save(user);
       user.setId(id);
       return user;
    }

    public User getUser(int id) {
        return repository.findById(id);
    }

    public void deleteUser(int id) {
        repository.deleteById(id);
    }

    public String login(String username, String password) throws NoSuchAlgorithmException {
        User user = repository.findByUsername(username);

        if (user == null) {
            return null;
        }

        String passwordHash = hashPassword(password);

        if (user.getPassword().equals(passwordHash)) {
            return createAuthToken(user);
        }
        return null;
    }

    private String createAuthToken(User user) {
        //return "Bearer " + user.getUsername();

        try {
            Algorithm algorithm = Algorithm.HMAC256("segredo");

            return JWT.create()
                    .withIssuer("apiToDO") // "issuer"
                    .withClaim("username", user.getUsername()) // Claim customizada
                    .withIssuedAt(new Date()) // "issuedAt"
                    .withExpiresAt(new Date(System.currentTimeMillis() + 3600000)) // "expiresAt" (Ex: 1 hora)
                    .sign(algorithm);


        } catch (JWTCreationException exception){
            // Invalid Signing configuration / Couldn't convert Claims.
            return null;
        }


    }
}



