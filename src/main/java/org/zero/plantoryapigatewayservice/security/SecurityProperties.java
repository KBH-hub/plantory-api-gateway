package org.zero.plantoryapigatewayservice.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    private List<String> whitelist = new ArrayList<>();

    public List<String> getWhitelist() { return whitelist; }
    public void setWhitelist(List<String> whitelist) { this.whitelist = whitelist; }
}

