package za.co.protogen.controller;

import com.baeldung.openapi.api.ReservationsApi;
import com.baeldung.openapi.model.ReservationDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import za.co.protogen.adapter.ReservationMappers;
import za.co.protogen.core.ReservationService;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping
public class resServiceApiController implements ReservationsApi {//9103

    private final ReservationService reservationService;

    private static final Logger logger = LoggerFactory.getLogger(resServiceApiController.class);

    public resServiceApiController(ReservationService service) {
        this.reservationService = service;
    }
    
    @Override
    public ResponseEntity<Void> createRes(ReservationDto reservationDto) {
        logger.info("adding reservation");
        reservationService.addReservation(ReservationMappers.RESERVATION_MAPPERS.dtoToEntity(reservationDto));
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @Override
    public ResponseEntity<List<ReservationDto>> getAllRes(){
        logger.info("getting all reservations");
        List<ReservationDto> reservationsDtos = ReservationMappers.RESERVATION_MAPPERS.lstEntityToDto((reservationService.getAllReservations()));
        return ResponseEntity.ok(reservationsDtos);
    }

    @Override
    public ResponseEntity<ReservationDto> getReservationById(Long id) {
        logger.info("getting reservation by id " + id);
        ReservationDto reservationsDto = ReservationMappers.RESERVATION_MAPPERS.entityToDto(reservationService.getReservationById(id));
        return ResponseEntity.ok(reservationsDto);
    }

    @Override
    public ResponseEntity<Void> removeRes(Long id) {
        logger.info("removing reservation by id" + id);
        reservationService.removeReservation(id);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
    
    @Override
    public ResponseEntity<Void> updateReservation(Long id, ReservationDto reservationDto
    ) {
        logger.info("updating reservation");
        reservationService.updateReservation(id, ReservationMappers.RESERVATION_MAPPERS.dtoToEntity(reservationDto));
        return ResponseEntity.status(HttpStatus.OK).build();
    }
    
    @Override
    public ResponseEntity<List<ReservationDto>> searchReservation(Long id, Long userId, Long reservationId, LocalDate fromDate, LocalDate toDate, String pickUpLocation, String dropOffLocation
    ) {
        logger.info("searching for reservations");
        Long idValue = (id != null) ? id : null;
        List<ReservationDto> lstReservationDto = ReservationMappers.RESERVATION_MAPPERS.lstEntityToDto(reservationService.searchReservations(idValue, userId, reservationId, fromDate, toDate, pickUpLocation, dropOffLocation));

        return ResponseEntity.ok(lstReservationDto);
    }

}
