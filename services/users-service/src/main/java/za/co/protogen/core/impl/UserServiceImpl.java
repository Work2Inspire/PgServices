package za.co.protogen.core.impl;

import com.baeldung.openapi.model.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import za.co.protogen.core.UserService;
import za.co.protogen.persistence.User;
import za.co.protogen.persistence.repository.UserRepository;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void addUser(User user) {
        userRepository.save(user);
    }

    @Override
    public void removeUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"User not found");
        }
        userRepository.deleteById(id);
    }
    @Override
    public User getUserById(Long id) {
        Optional<User> userOptional = userRepository.findById(id);
        return userOptional.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"User not found"));
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void updateUser(Long id, User updatedUser) {
        User existingUser = getUserById(id);
        if (existingUser != null) {
            existingUser.setId(updatedUser.getId());
            existingUser.setFirstName(updatedUser.getFirstName());
            existingUser.setLastName(updatedUser.getLastName());
            existingUser.setDateOfBirth(updatedUser.getDateOfBirth());
            existingUser.setRsaId(updatedUser.getRsaId());
            userRepository.save(existingUser);
        }
    }

    @Override
    public List<User> searchUsers(Long id, String firstName, String lastName, LocalDate dateOfBirth, String rsaId) {

        User searchUser = new User();
        searchUser.setId(id);
        searchUser.setFirstName(firstName);
        searchUser.setLastName(lastName);
        searchUser.setDateOfBirth(dateOfBirth);
        searchUser.setRsaId(rsaId);

        // Create an ExampleMatcher
        ExampleMatcher matcher = ExampleMatcher.matchingAny() // Match ANY property
                .withIgnoreNullValues() // Ignore null fields
                .withIgnoreCase(); // Ignore case sensitivity

        // Create Example instance
        Example<User> example = Example.of(searchUser, matcher);

        // Find all matching users
        return userRepository.findAll(example);

    }

}
