package za.co.protogen.controller;


import com.baeldung.openapi.api.UsersApi;
import com.baeldung.openapi.model.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import za.co.protogen.adapter.userMappers;
import za.co.protogen.config.ApplicationProperties;
import za.co.protogen.core.UserService;
import za.co.protogen.core.impl.UserServiceImpl;

import javax.validation.Valid;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping
public class UsersServiceApiController implements UsersApi {
    
    private RestTemplate restTemplate;
    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(UsersServiceApiController.class);

    public UsersServiceApiController(UserService userService,RestTemplate restTemplate) {
        this.userService = userService;
        this.restTemplate=restTemplate;
    }

    @Override
    public ResponseEntity<Void> addUser(@RequestBody UserDto userDto) {
        userService.addUser(userMappers.USER_MAPPERS.userDtoToUserEntity(userDto));
        logger.info("adding user");

        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @Override
    public ResponseEntity<List<UserDto>> getAllUsers() {
        logger.info("getting all users");
        List<UserDto> userDtos = userMappers.USER_MAPPERS.userEntityToUserDto(userService.getAllUsers());

        return ResponseEntity.ok(userDtos);
    }

    @Override
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {
        logger.info("getting user by id " + id);
        UserDto userDto = userMappers.USER_MAPPERS.userEntityToUserDto(userService.getUserById(id.longValue()));
        return ResponseEntity.ok(userDto);
    }

    @Override
    public ResponseEntity<Void> removeUser(@PathVariable Long id) {
        userService.removeUser(id.longValue());
        logger.info("removing user by id" + id);
        return ResponseEntity.status(HttpStatus.OK).build();
    }


    @Override
    public ResponseEntity<List<UserDto>> searchUsers( Long id, String firstName, String lastName, LocalDate dateOfBirth, String rsaId, String username) {
        logger.info("searching all users");
        Long idValue = (id != null) ? id.longValue() : null;
        List<UserDto> lstUserDto = userMappers.USER_MAPPERS.userEntityToUserDto(userService.searchUsers(idValue, firstName, lastName, dateOfBirth, rsaId,username));

        return ResponseEntity.ok(lstUserDto);
    }

    @Override
    public ResponseEntity<Void> updateUser(@PathVariable Long id, @RequestBody UserDto userDto) {
        userService.updateUser(id, userMappers.USER_MAPPERS.userDtoToUserEntity(userDto));
        logger.info("updating user");
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
