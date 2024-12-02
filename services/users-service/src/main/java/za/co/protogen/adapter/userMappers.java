package za.co.protogen.adapter;

import com.baeldung.openapi.model.UserDto;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import za.co.protogen.persistence.User;

import java.util.List;

@Mapper(componentModel = "spring")
public interface userMappers {
    userMappers USER_MAPPERS = Mappers.getMapper(userMappers.class);
    //Convert Entity to and from userDto
    User userDtoToUserEntity(UserDto userDto);
    UserDto userEntityToUserDto(User user);
    //Convert list of Entity to List of userDto
    List<UserDto> userEntityToUserDto(List<User> user);


}