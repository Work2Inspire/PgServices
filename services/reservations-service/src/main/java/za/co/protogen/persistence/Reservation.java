package za.co.protogen.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDate;
@Entity
@Table(name = "Reservations")
public class Reservation {
    @Id
    @Column(name = "Id")
    private Long id;//The unique identifier for the reservation (type: Long).
    @Column(name = "User_Id")
    private Long userId;//The unique identifier for the user associated with the reservation (type: Long).
    @Column(name = "Car_Id")
    private Long carId;//The unique identifier for the car reserved (type: Long).
    @Column(name = "From_Date")
    private LocalDate fromDate;//The starting date of the reservation (type: LocalDate).
    @Column(name = "To_Date")
    private LocalDate toDate;//The ending date of the reservation (type: LocalDate).
    @Column(name = "Pick_Up_Location")
    private String pickUpLocation;//The location where the car will be picked up.
    @Column(name = "Drop_Off_Location")
    private String dropOffLocation;//The location where the car will be dropped off.

    @Override
    public String toString() {
        return "Reservation {id='"+id+"', userId="+userId+"', carId="+carId+"', fromDate="+fromDate+"', toDate="+toDate+"', pickUpLocation="+pickUpLocation+"', dropoffLocation="+ dropOffLocation +" }";
    }//For better retrieval

    //getter
    public Long getId() {
        return id;
    }
    public Long getUserId() {
        return userId;
    }
    public Long getCarId() {
        return carId;
    }
    public LocalDate getFromDate() {
        return fromDate;
    }
    public LocalDate getToDate() {
        return toDate;
    }
    public String getPickUpLocation() {
        return pickUpLocation;
    }
    public String getDropOffLocation() {
        return dropOffLocation;
    }
    //setter

    public void setId(Long id) {
        this.id = id;
    }
    public void setUserId(Long userId) {
        this.userId = userId;
    }
    public void setCarId(Long carId) {
        this.carId = carId;
    }
    public void setFromDate(LocalDate fromDate) {
        this.fromDate = fromDate;
    }
    public void setToDate(LocalDate toDate) {
        this.toDate = toDate;
    }
    public void setPickUpLocation(String pickUpLocation) {
        this.pickUpLocation = pickUpLocation;
    }
    public void setDropOffLocation(String dropOffLocation) {
        this.dropOffLocation = dropOffLocation;
    }

}
