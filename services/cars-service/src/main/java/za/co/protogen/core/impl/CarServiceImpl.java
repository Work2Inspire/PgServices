package za.co.protogen.core.impl;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import za.co.protogen.core.CarService;
import za.co.protogen.persistence.Car;
import za.co.protogen.persistence.repository.CarRepository;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Service
public class CarServiceImpl implements CarService {

    private final CarRepository carRepository;

    public CarServiceImpl(CarRepository carRepository) {
        this.carRepository = carRepository;
    }

    @Override
    public void addCar(Car car) {
        carRepository.save(car);
    }

    @Override
    public List<Car> getAllCars() {
        return carRepository.findAll().stream().toList();
    }

    @Override
    public void removeCar(String vin) {
        if (!carRepository.existsById(vin)) {
            throw new IllegalStateException("Car not found");
        }
        carRepository.deleteById(vin);
    }

    @Override
    public Car getCarByVin(String vin) {
        Optional<Car> carOptional = carRepository.findById(vin);
        return carOptional.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Car not found"));
    }

    @Override
    public void updateCar(String vin, Car updateInfo) {
        Car existingCar = getCarByVin(vin);
        if (existingCar != null) {

            if (updateInfo.getVin() != null) {
                existingCar.setVin(updateInfo.getVin());
            }
            if (updateInfo.getMake() != null) {
                existingCar.setMake(updateInfo.getMake());
            }
            if (updateInfo.getModel() != null) {
                existingCar.setModel(updateInfo.getModel());
            }
            if (updateInfo.getYear() != null) {
                existingCar.setYear(updateInfo.getYear());
            }
            if (updateInfo.getColor() != null) {
                existingCar.setColor(updateInfo.getColor());
            }
            if (updateInfo.getEngine() != null) {
                existingCar.setEngine(updateInfo.getEngine());
            }
            if (updateInfo.getTransmission() != null) {
                existingCar.setTransmission(updateInfo.getTransmission());
            }
            if (updateInfo.getFuelType() != null) {
                existingCar.setFuelType(updateInfo.getFuelType());
            }
            if (updateInfo.getMileage() != null) {
                existingCar.setMileage(updateInfo.getMileage());
            }
            if (updateInfo.getPrice() != null) {
                existingCar.setPrice(updateInfo.getPrice());
            }
            if (updateInfo.getOwnerId() != null) {
                existingCar.setOwnerId(updateInfo.getOwnerId());
            }
            if (!updateInfo.getFeatures().isEmpty()) {
                existingCar.setFeatures(updateInfo.getFeatures());
            }


            carRepository.save(existingCar);
        }
    }

    public List<Car> getCarsByMake(String make){
        return carRepository.findAll().stream().filter(a-> a.getMake().equals(make)).toList();
    }

    public List<Car> getCarsByYear(int year){
        return carRepository.findAll().stream().filter(a-> a.getYear().equals(year)).toList();
    }

    public List<Car> getCarsByColor(String color){
        return carRepository.findAll().stream().filter(a-> a.getColor().equals(color)).toList();
    }

    public Double calculateAverageMileage(){
        return carRepository.totalMileage();
    }

    public List<Car> findCheapestCar(){
        return carRepository.findAll().stream()
                .min(Comparator.comparing(Car::getPrice)).stream().toList();
    }

    public List<Car> findMostExpensiveCar(){
        return carRepository.findAll().stream()
                .max(Comparator.comparing(Car::getPrice)).stream().toList();
    }

    public List<Car> findNewestCar(){
        return carRepository.findAll().stream()
                .max(Comparator.comparing(Car::getYear)).stream().toList();
    }

    public List<Car> findOldestCar(){
        return carRepository.findAll().stream()
                .min(Comparator.comparing(Car::getYear)).stream().toList(); // Return null if no cars exist
    }

    @Override
    public List<Car> searchCars( String vin, String make, String model, Integer year, String color, String engine, String transmission, String fuelType, Double mileage, Double price, Long ownerId, List<String> features) {

        Car searchCar = new Car();
        searchCar.setVin(vin);
        searchCar.setMake(make);
        searchCar.setModel(model);
        searchCar.setYear(year);
        searchCar.setColor(color);
        searchCar.setEngine(engine);
        searchCar.setTransmission(transmission);
        searchCar.setFuelType(fuelType);
        searchCar.setMileage(mileage);
        searchCar.setPrice(price);
        searchCar.setOwnerId(ownerId);
        searchCar.setFeatures(features);

        // Create an ExampleMatcher
        ExampleMatcher matcher = ExampleMatcher.matchingAny() // Match ANY property
                .withIgnoreNullValues() // Ignore null fields
                .withIgnoreCase(); // Ignore case sensitivity

        // Create Example instance
        Example<Car> example = Example.of(searchCar, matcher);

        // Find all matching cars
        return carRepository.findAll(example);

    }

}
