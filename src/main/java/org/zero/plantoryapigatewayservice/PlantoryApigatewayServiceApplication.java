package org.zero.plantoryapigatewayservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan(basePackages = "org.zero.plantoryapigatewayservice")
public class PlantoryApigatewayServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PlantoryApigatewayServiceApplication.class, args);
    }

}
