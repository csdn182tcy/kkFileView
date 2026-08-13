package cn.keking.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 预览鉴权配置，对齐 Tw.Bpm WebApiToken（roadflow-token）。
 */
@Component
public class PreviewAuthProperties {

    @Value("${preview.auth.enabled:false}")
    private boolean enabled;

    @Value("${preview.auth.token-secret:}")
    private String tokenSecret;

    @Value("${preview.auth.token-name:roadflow-token}")
    private String tokenName;

    @Value("${preview.auth.issuer:tw369.com}")
    private String issuer;

    @Value("${preview.auth.audience:tw369.com}")
    private String audience;

    @Value("${preview.auth.cookie-max-age:86400}")
    private int cookieMaxAge;

    public boolean isEnabled() {
        return enabled;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public String getTokenName() {
        return tokenName;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAudience() {
        return audience;
    }

    public int getCookieMaxAge() {
        return cookieMaxAge;
    }

    public boolean isConfigured() {
        return tokenSecret != null && !tokenSecret.trim().isEmpty();
    }
}
