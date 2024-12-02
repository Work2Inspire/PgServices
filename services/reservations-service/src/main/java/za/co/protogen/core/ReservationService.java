package za.co.protogen.core;


import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.RequestParam;
import za.co.protogen.persistence.Reservation;

import javax.validation.Valid;
import java.time.LocalDate;
import java.util.List;

public interface ReservationService {

    void addReservation(Reservation reservation);//Adds a new reservation to the service.

    List<Reservation> getAllReservations();//Retrieves a list of all reservations in the service.

    void removeReservation(Long id);//Removes a reservation from the service.

    Reservation getReservationById(Long id);// Retrieves a reservation from the service based on its unique identifier

    void updateReservation(Long id, Reservation updateReservationInfo);//Updates the information or attributes of a reservation.

    List<Reservation> searchReservations( Long id, Long userId, Long carId, LocalDate fromDate, LocalDate toDate, String pickUpLocation, String dropOffLocation);//Searches for reservations based on various criteria, such as user ID, car ID, dates, etc.


}
