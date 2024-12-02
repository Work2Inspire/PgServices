package za.co.protogen.adapter;

import com.baeldung.openapi.model.CarDto;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;
import za.co.protogen.persistence.Car;

import java.util.List;

@Mapper(componentModel = "spring")
public interface CarMappers {
    CarMappers CAR_MAPPERS = Mappers.getMapper(CarMappers.class);

    //Mapping from one layer to another
    Car carDtoTocarEntity(CarDto carDto);
    CarDto carEntityToCarDto(Car car);
    List<CarDto> carEntityToCarDto(List<Car> car);
}
