package za.co.protogen.persistence.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import za.co.protogen.persistence.Car;


@Repository
public interface CarRepository extends JpaRepository<Car, String> {

    //get mileage sum of all items in repository when totalMileage is called
    @Query(value = "SELECT SUM(Mileage) FROM Cars",nativeQuery = true)
    Double totalMileage();

}
