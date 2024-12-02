package za.co.protogen.persistence;

import jakarta.persistence.*;
import za.co.protogen.adapter.StringListConverter;

import java.util.List;

enum Transmission {MANUAL,AUTOMATIC,CVT}
enum FuelType {GASOLINE, DIESEL, ELECTRIC}

@Entity
@Table(name = "Cars")
public class Car {
    @Id
    @Column(name = "Vin")
    private String vin;//A unique identifier assigned to the car (Vehicle Identification Number).
    @Column(name = "Make")
    private String make;//The car's manufacturer or brand.
    @Column(name = "Model")
    private String model;//The specific model name or number.
    @Column(name = "Man_Year")
    private Integer year;//The year the car was manufactured.
    @Column(name = "Color")
    private String color;//The color of the car's exterior.
    @Column(name = "Engine")
    private String engine;//Details about the car's engine, such as type, displacement, or horsepower.
    @Column(name = "Transmission")
    @Enumerated(EnumType.STRING)
    private Transmission transmission;//The type of transmission the car has (e.g., manual, automatic).
    @Column(name = "Fuel_Type")
    @Enumerated(EnumType.STRING)
    private FuelType fuelType;//The type of fuel the car uses (e.g., gasoline, diesel, electric).
    @Column(name = "Mileage")
    private Double mileage;//The number of miles the car has traveled.
    @Column(name = "Price")
    private Double price;//The price of the car.
    @Column(name = "Owner_ID")
    private Long ownerId;//The owner's unique identifier.
    @Convert(converter = StringListConverter.class)
    @Column(name = "Features")
    private List<String> features;//A list of additional features or options the car may have, such as a navigation system, sunroof, etc.

    @Override
    public String toString() {
        return "Car{make='"+make+"', model="+model+"', year="+year+"', color="+color+"', engine="+engine+"', transmission="+transmission+"', fuelType="+fuelType+"', mileage="+mileage+"', vin="+vin+"', price="+price+"', ownerId="+ownerId+"', features="+features+" }";
    }//For better retrieval

    public void setMake(String make){
        this.make=make;
    }
    public void setModel(String model){
        this.model=model;
    }
    public void setYear(Integer year){
        this.year=year;
    }
    public void setColor(String color){
        this.color=color;
    }
    public void setEngine(String engine){
        this.engine=engine;
    }
    public void setTransmission(String Transmission){
        try {
            this.transmission=za.co.protogen.persistence.Transmission.valueOf(Transmission.toUpperCase());
        }catch (Exception e){
            System.out.println("Error: Defaulting to Null");
            this.transmission=null;
        }
    }//Find and set etransmission enum value using input Transmission string else set null

    public void setFuelType(String FuelType){
        try {
            this.fuelType = za.co.protogen.persistence.FuelType.valueOf(FuelType.toUpperCase());
        }catch (Exception e){
            System.out.println("Error: Defaulting to Null");
            this.fuelType=null;
        }

    }//Use incoming string to set Fuel but default to null if string is incorrect

    public void setMileage(Double mileage){
        this.mileage=mileage;
    }
    public void setVin(String vin){
        this.vin=vin;
    }
    public void setPrice(Double price){
        this.price=price;
    }
    public void setOwnerId(Long ownerId){
        this.ownerId=ownerId;
    }
    public void setFeatures(List<String> features){
        this.features=features;
    }


    //getters methods for every property declared-----------------------------------------------
    public String getMake(){
        return this.make;
    }
    public String getModel(){
        return this.model;
    }
    public Integer getYear(){
        return this.year;
    }
    public String getColor(){
        return this.color;
    }
    public String getEngine(){
        return this.engine;
    }
    public String getTransmission(){
        if (this.transmission == null) {
            return null;
        }
        return this.transmission.name();
    }
    public String getFuelType(){
        if (this.fuelType == null) {
            return null;
        }
        return this.fuelType.name();
    }
    public Double getMileage(){
        return this.mileage;
    }
    public String getVin(){
        return this.vin;
    }
    public Double getPrice(){
        return this.price;
    }
    public Long getOwnerId(){
        return this.ownerId;
    }
    public List<String> getFeatures(){
        return features;
    }

}