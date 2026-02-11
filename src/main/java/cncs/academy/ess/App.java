package cncs.academy.ess;

import cncs.academy.ess.controller.AuthorizationMiddleware;
import cncs.academy.ess.controller.TodoController;
import cncs.academy.ess.controller.TodoListController;
import cncs.academy.ess.controller.UserController;
import cncs.academy.ess.repository.memory.InMemoryTodoRepository;
import cncs.academy.ess.repository.memory.InMemoryTodoListsRepository;
import cncs.academy.ess.repository.memory.InMemoryUserRepository;
import cncs.academy.ess.service.DuplicateUserException;
import cncs.academy.ess.service.TodoListsService;
import cncs.academy.ess.service.TodoUserService;
import cncs.academy.ess.service.TodoService;
import io.javalin.Javalin;
import io.javalin.community.ssl.SslPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

import java.security.NoSuchAlgorithmException;

import static cncs.academy.ess.service.security.PasswordUtils.generateSalt;

public class App {

/*
    private static byte[] hashPassword(String password, byte[] salt, int iterations, int keyLength) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
*/

    public static void main(String[] args) throws Exception {
       /* Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(it -> {
                    it.anyHost();
                });
            });
       }).start(7100);*/


/*
        byte[] hashedPassword = hashPassword("123", generateSalt() , 10, 256);
*/


        SslPlugin plugin = new SslPlugin(conf -> {
            conf.pemFromPath(
                    "/Users/utilizador/Desktop/Lab2/cert.pem",
                    "/Users/utilizador/Desktop/Lab2/key.pem",
                    "123456");
            conf.sniHostCheck = false;
        });

        Javalin app = Javalin.create(javalinConfig -> {
            javalinConfig.registerPlugin(plugin);
        }).start();


        // Initialize routes for user management
        InMemoryUserRepository userRepository = new InMemoryUserRepository();
        TodoUserService userService = new TodoUserService(userRepository);
        UserController userController = new UserController(userService);

        InMemoryTodoListsRepository listsRepository = new InMemoryTodoListsRepository();
        TodoListsService toDoListService = new TodoListsService(listsRepository);
        TodoListController todoListController = new TodoListController(toDoListService);

        InMemoryTodoRepository todoRepository = new InMemoryTodoRepository();
        TodoService todoService = new TodoService(todoRepository, listsRepository);
        TodoController todoController = new TodoController(todoService, toDoListService);

        AuthorizationMiddleware authMiddleware = new AuthorizationMiddleware(userRepository);


        // CORS
        app.before(ctx -> {
            ctx.header("Access-Control-Allow-Origin", "*");
            ctx.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            ctx.header("Access-Control-Allow-Headers", "*");
        });
        // Authorization middleware
        app.before(authMiddleware::handle);

        // User management
        app.post("/user", userController::createUser);
        app.get("/user/{userId}", userController::getUser);
        app.delete("/user/{userId}", userController::deleteUser);
        app.post("/login", userController::loginUser);

        // "To do" lists management
        /* POST /todolist
          {
              "listName": "Shopping list"
          }
         */
        app.post("/todolist", todoListController::createTodoList);
        app.get("/todolist", todoListController::getAllTodoLists);
        app.get("/todolist/{listId}", todoListController::getTodoList);

        // "To do" list items management
        /* POST /todo/item
          {
              "description": "Buy milk",
              "listId": 1
          }
         */
        app.post("/todo/item", todoController::createTodoItem);
        /* GET /todo/1/tasks */
        app.get("/todo/{listId}/tasks", todoController::getAllTodoItems);
        /* GET /todo/1/tasks/1 */
        app.get("/todo/{listId}/tasks/{taskId}", todoController::getTodoItem);
        /* DELETE /todo/1/tasks/1 */
        app.delete("/todo/{listId}/tasks/{taskId}", todoController::deleteTodoItem);

        fillDummyData(userService, toDoListService, todoService);
    }

    private static void fillDummyData(
            TodoUserService userService,
            TodoListsService toDoListService,
            TodoService todoService) throws NoSuchAlgorithmException, DuplicateUserException {


        userService.addUser("user1", "password1");


        userService.addUser("user2", "password2");
        userService.addUser("user3", "password3");

        userService.addUser("user69", "password69");

        toDoListService.createTodoListItem("Shopping list", 1);
        toDoListService.createTodoListItem("Other", 1);
        toDoListService.createTodoListItem("Shopping list2", 2);
        toDoListService.createTodoListItem("Shopping list3", 2);
        toDoListService.createTodoListItem("Other", 2);
        toDoListService.createTodoListItem("Other", 3);
        toDoListService.createTodoListItem("Shopping list4", 3);
        toDoListService.createTodoListItem("Shopping list5", 3);
        toDoListService.createTodoListItem("Other1", 3);
        toDoListService.createTodoListItem("Other2", 3);
        todoService.createTodoItem("Bread", 1);
        todoService.createTodoItem("Milk", 1);
        todoService.createTodoItem("Eggs", 1);
        todoService.createTodoItem("Cheese", 1);
        todoService.createTodoItem("Butter", 1);

    }
}
