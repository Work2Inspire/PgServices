package za.co.protogen.adapter;

import com.baeldung.openapi.model.ReservationDto;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;
import za.co.protogen.persistence.Reservation;

import java.util.List;

@Mapper(componentModel = "spring")
public interface ReservationMappers {
    ReservationMappers RESERVATION_MAPPERS = Mappers.getMapper(ReservationMappers.class);

    //convert dto to entity model
    Reservation dtoToEntity(ReservationDto dto);
    //convert entity model to dto
    ReservationDto entityToDto(Reservation entity);
    //convert EntityList into DtoList
    List<ReservationDto> lstEntityToDto(List<Reservation> entity);
}
