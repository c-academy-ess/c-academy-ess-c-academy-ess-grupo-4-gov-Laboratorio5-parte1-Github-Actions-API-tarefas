package cncs.academy.ess.controller;

import cncs.academy.ess.controller.messages.ErrorMessage;
import cncs.academy.ess.controller.messages.UserAddRequest;
import cncs.academy.ess.controller.messages.UserLoginRequest;
import cncs.academy.ess.controller.messages.UserResponse;
import cncs.academy.ess.model.User;
import cncs.academy.ess.service.DuplicateUserException;
import cncs.academy.ess.service.TodoUserService;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;

// Imports para Zip Slip
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final TodoUserService userService;

    public UserController(TodoUserService userService) {
        this.userService = userService;
    }

    public void createUser(Context ctx) throws NoSuchAlgorithmException, DuplicateUserException {
        UserAddRequest userRequest = ctx.bodyAsClass(UserAddRequest.class);
        try {
            User user = userService.addUser(userRequest.username, userRequest.password);
            UserResponse response = new UserResponse(user.getId(), user.getUsername());
            log.info("Create user: {}", userRequest.username);
            ctx.status(201).json(response);
        } catch (DuplicateUserException e) {
            log.info("User duplicated: {}", userRequest.username);
            ctx.status(409).json(new ErrorMessage(e.getMessage()));
        }
    }

    public void getUser(Context ctx) {
        int userId = Integer.parseInt(ctx.pathParam("userId"));
        User user = userService.getUser(userId);
        if (user != null) {
            UserResponse response = new UserResponse(user.getId(), user.getUsername());
            ctx.status(200).json(response);
        } else {
            ctx.status(404).json(new ErrorMessage("User not found"));
        }
    }

    public void deleteUser(Context ctx) {
        int userId = Integer.parseInt(ctx.pathParam("userId"));
        userService.deleteUser(userId);
        ctx.status(204);
    }

    public void loginUser(Context ctx) throws NoSuchAlgorithmException {
        UserLoginRequest userRequest = ctx.bodyAsClass(UserLoginRequest.class);
        log.info("Login user: {}", userRequest.username);

        String token = userService.login(userRequest.username, userRequest.password);

        if (token != null) {
            ctx.status(200).json(token);
        } else {
            ctx.status(401).json(new ErrorMessage("Invalid username or password"));
        }
    }

    public void loginUserHash(Context ctx) throws NoSuchAlgorithmException {
        UserLoginRequest userRequest = ctx.bodyAsClass(UserLoginRequest.class);
        log.info("Login user: {}", userRequest.username);
        String token = userService.login(userRequest.username, userRequest.password);
        if (token != null) {
            ctx.status(200).json(token);
        } else {
            ctx.status(401).json(new ErrorMessage("Invalid username or password"));
        }
    }

    // ============================
    // Método vulnerável (Zip Slip)
    // ============================
    public void addProfilePicture(Context ctx) {
        String userId = ctx.pathParam("userId");
        String destinationDir = "/app/profiles/" + userId;

        try {
            InputStream zipInput = ctx.uploadedFile("profileZip").content();
            ZipInputStream zis = new ZipInputStream(zipInput);
            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                // Vulnerabilidade: uso direto do nome da entry (Zip Slip)
                File profilePic = new File(destinationDir, entry.getName());

                // Criação de diretórios sem validação
                profilePic.getParentFile().mkdirs();

                // Escrita do ficheiro sem validação de path traversal
                Files.copy(
                        zis,
                        profilePic.toPath(),
                        StandardCopyOption.REPLACE_EXISTING
                );
            }

            ctx.status(200).result("Profile pictures uploaded successfully");
        } catch (Exception e) {
            ctx.status(500).result("Error uploading profile pictures");
        }
    }
}