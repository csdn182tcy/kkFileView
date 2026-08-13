package cn.keking.utils;

import cn.keking.config.PreviewAuthProperties;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class RoadflowTokenValidatorTest {

    private static final String USER_TOKEN =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySWQiOiJlYjAzMjYyYy1hYjYwLTRiYzYtYTRjMC05NmU2NmE0MjI5ZmUiLCJDbGllbnRJZCI6IjgzNjI0MmQ1LWVhNzMtNDJmZC05ZDI2LTRjMTRlMmMzNjlhYyIsIkxvZ2luVHlwZSI6IjAiLCJleHAiOjE3ODMwODQxNjAsImlzcyI6InR3MzY5LmNvbSIsImF1ZCI6InR3MzY5LmNvbSJ9.uY8tv_FGAjE9CgiLvi7SktF6iN4VN80OQNgxDHEU2m0";

    @Test
    void validatesProductionUserToken() throws Exception {
        RoadflowTokenValidator validator = new RoadflowTokenValidator(properties(
                true, "abcdefghijklmnopqrstuvwxyz", "tw369.com", "tw369.com"));
        assertNotNull(validator.validate(USER_TOKEN));
    }

    @Test
    void rejectsWhenSecretEmpty() throws Exception {
        RoadflowTokenValidator validator = new RoadflowTokenValidator(properties(
                true, "", "tw369.com", "tw369.com"));
        assertNull(validator.validate(USER_TOKEN));
    }

    @Test
    void rejectsWhenSecretWrong() throws Exception {
        RoadflowTokenValidator validator = new RoadflowTokenValidator(properties(
                true, "wrong-secret", "tw369.com", "tw369.com"));
        assertNull(validator.validate(USER_TOKEN));
    }

    private static PreviewAuthProperties properties(boolean enabled, String secret,
                                                    String issuer, String audience) throws Exception {
        PreviewAuthProperties properties = new PreviewAuthProperties();
        setField(properties, "enabled", enabled);
        setField(properties, "tokenSecret", secret);
        setField(properties, "issuer", issuer);
        setField(properties, "audience", audience);
        return properties;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
