package cncs.academy.ess.service;


import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import cncs.academy.ess.service.security.PasswordUtils;

import java.security.NoSuchAlgorithmException;

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
        return "Bearer " + user.getUsername();
    }
}



