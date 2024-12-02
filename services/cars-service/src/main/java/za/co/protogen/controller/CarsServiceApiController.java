package za.co.protogen.controller;

import com.baeldung.openapi.api.CarsApi;
import com.baeldung.openapi.model.CarDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import za.co.protogen.adapter.CarMappers;
import za.co.protogen.core.CarService;

import java.util.List;

@RestController
@RequestMapping
public class CarsServiceApiController implements CarsApi {
    private final CarService carService;

    private static final Logger logger = LoggerFactory.getLogger(CarsServiceApiController.class);

    public CarsServiceApiController(CarService carService) {
        this.carService = carService;
    }

    @Override
    public ResponseEntity<Void> createCar(@RequestBody CarDto carDto) {
        logger.info("adding car");
        carService.addCar(CarMappers.CAR_MAPPERS.carDtoTocarEntity(carDto));
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @Override
    public ResponseEntity<List<CarDto>> getAll() {
        logger.info("getting all cars");
        List<CarDto> carsDtos = CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.getAllCars());
        return ResponseEntity.ok(carsDtos);
    }

    @Override
    public ResponseEntity<CarDto> getByVin(@PathVariable String vin) {
        logger.info("getting car by vin " + vin);
        CarDto carsDto = CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.getCarByVin(vin));
        return ResponseEntity.ok(carsDto);
    }

    @Override
    public ResponseEntity<Void> deleteCar(@PathVariable String vin) {
        logger.info("removing car by id" + vin);
        carService.removeCar(vin);
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @Override
    public ResponseEntity<Void> updateCar(@PathVariable("vin") String vin, @RequestBody CarDto carDto) {
        logger.info("updating car");

        carService.updateCar(vin, CarMappers.CAR_MAPPERS.carDtoTocarEntity(carDto));
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @Override
    public ResponseEntity<Double> getAvgMileage(){
        logger.info("calculating average mileage");
        return ResponseEntity.ok(carService.calculateAverageMileage());
    }

    @Override
    public ResponseEntity<List<CarDto>> getByColor(@PathVariable String color){
        logger.info("getting car by color: "+color );
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.getCarsByColor(color)));
    }

    @Override
    public ResponseEntity<List<CarDto>> getByMake(@PathVariable String make){
        logger.info("getting car by make: "+make );
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.getCarsByMake(make)));
    }

    @Override
    public ResponseEntity<List<CarDto>> getByYear(@PathVariable Integer year){
        logger.info("getting car by year: "+year );
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.getCarsByYear(year)));
    }

    @Override
    public ResponseEntity<List<CarDto>> getCheapest(){
        logger.info("getting cheapest car(s)");
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.findCheapestCar()));
    }

    @Override
    public ResponseEntity<List<CarDto>> getExpensive(){
        logger.info("getting most expensive car(s)");
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.findMostExpensiveCar()));
    }

    @Override
    public ResponseEntity<List<CarDto>> getNewest(){
        logger.info("getting newest car(s)");
        carService.findNewestCar();
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.findNewestCar()));
    }

    @Override
    public ResponseEntity<List<CarDto>> getOldest(){
        logger.info("getting oldest car(s)");
        return ResponseEntity.ok(CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.findOldestCar()));
    }

    @Override
    public ResponseEntity<List<CarDto>> searchCars( String vin, String make, String model, Integer year, String color, String engine, String transmission, String fuelType, Double mileage, Double price, Long ownerId, List<String> features) {

        logger.info("searching for cars");
        String vinValue = (vin != null) ? vin : null;
        List<CarDto> lstCarDto = CarMappers.CAR_MAPPERS.carEntityToCarDto(carService.searchCars(vinValue, make, model, year, color, engine, transmission, fuelType, mileage, price, ownerId, features));

        return ResponseEntity.ok(lstCarDto);
    }

}
