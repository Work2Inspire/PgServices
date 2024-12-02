package za.co.protogen.core;

import za.co.protogen.persistence.Car;

import java.util.List;

public interface CarService {

    void addCar(Car car);//Adds a new car to the service.

    List<Car> getAllCars();//Retrieves a list of all cars in the service.

    void removeCar(String vin);//Removes a car from the service.

    Car getCarByVin(String vin);//Retrieves a car from the service based on its Vin.

    void updateCar(String vin, Car updatedUser);//Updates the information or attributes of a car.

    List<Car> getCarsByMake(String make);//Retrieves a list of cars based on the specified make.

    List<Car> getCarsByYear(int year);//Retrieves a list of cars based on the specified year.

    List<Car> getCarsByColor(String color);//Retrieves a list of cars based on the specified color.

    Double calculateAverageMileage();//Calculates the average mileage of all cars in the service.

    List<Car> findCheapestCar();//Finds the cheapest car in the service.
    List<Car> findMostExpensiveCar();//Finds the most expensive car in the service.
    List<Car> findNewestCar();//Finds the newest car in the service based on the manufacturing year.
    List<Car> findOldestCar();//Finds the oldest car in the service based on the manufacturing year.

    List<Car> searchCars( String vin, String make, String model, Integer year, String color, String engine, String transmission, String fuelType, Double mileage, Double price, Long ownerId, List<String> features);//Searches for cars based on various criteria, such as make, model, price range, etc.










}
