package cn.keking.utils;

import cn.keking.config.PreviewAuthProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;

/**
 * 校验 Tw.Bpm 签发的 roadflow-token（JWT / HmacSha256）。
 * 使用原生 HMAC 验签，兼容 BPM 短密钥（jjwt 0.11+ 会拒绝 &lt;256bit 的 HS256 密钥）。
 */
@Component
public class RoadflowTokenValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoadflowTokenValidator.class);
    private static final String EMPTY_GUID = "00000000-0000-0000-0000-000000000000";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final PreviewAuthProperties previewAuthProperties;

    public RoadflowTokenValidator(PreviewAuthProperties previewAuthProperties) {
        this.previewAuthProperties = previewAuthProperties;
    }

    /**
     * @return 有效则返回 UserId，否则 null
     */
    public String validate(String token) {
        if (!StringUtils.hasText(token)) {
            LOGGER.warn("roadflow-token 缺失");
            return null;
        }
        if (!previewAuthProperties.isConfigured()) {
            LOGGER.error("preview.auth.token-secret 未配置，无法校验 token");
            return null;
        }
        try {
            String trimmed = token.trim();
            String[] parts = trimmed.split("\\.");
            if (parts.length != 3) {
                LOGGER.warn("roadflow-token 格式无效");
                return null;
            }
            if (!verifySignature(parts[0], parts[1], parts[2], previewAuthProperties.getTokenSecret())) {
                LOGGER.warn("roadflow-token 验签失败（请核对 preview.auth.token-secret 是否与 BPM TokenSecret 一致）");
                return null;
            }

            JsonNode payload = OBJECT_MAPPER.readTree(decodeBase64Url(parts[1]));
            if (!matchesExpectedValue(payload, "iss", previewAuthProperties.getIssuer())) {
                LOGGER.warn("roadflow-token issuer 不匹配");
                return null;
            }
            if (!matchesAudience(payload, previewAuthProperties.getAudience())) {
                LOGGER.warn("roadflow-token audience 不匹配");
                return null;
            }

            JsonNode expNode = payload.get("exp");
            if (expNode == null || !expNode.canConvertToLong()) {
                LOGGER.warn("roadflow-token 缺少 exp");
                return null;
            }
            long expSeconds = expNode.asLong();
            if (expSeconds * 1000L < System.currentTimeMillis()) {
                LOGGER.warn("roadflow-token 已过期: exp={}", new Date(expSeconds * 1000L));
                return null;
            }

            String userId = readTextClaim(payload, "UserId");
            if (!StringUtils.hasText(userId) || EMPTY_GUID.equalsIgnoreCase(userId)) {
                LOGGER.warn("roadflow-token UserId 无效: {}", userId);
                return null;
            }
            return userId;
        } catch (Exception e) {
            LOGGER.warn("roadflow-token 解析失败: {}", e.getMessage());
            return null;
        }
    }

    private static boolean verifySignature(String header, String payload, String signature, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] expected = mac.doFinal((header + "." + payload).getBytes(StandardCharsets.UTF_8));
        byte[] actual = Base64.getUrlDecoder().decode(padBase64Url(signature));
        return MessageDigest.isEqual(expected, actual);
    }

    private static String decodeBase64Url(String value) {
        return new String(Base64.getUrlDecoder().decode(padBase64Url(value)), StandardCharsets.UTF_8);
    }

    private static String padBase64Url(String value) {
        int mod = value.length() % 4;
        if (mod == 0) {
            return value;
        }
        return value + "====".substring(mod);
    }

    private static boolean matchesExpectedValue(JsonNode payload, String name, String expected) {
        JsonNode node = payload.get(name);
        return node != null && expected.equals(node.asText());
    }

    private static boolean matchesAudience(JsonNode payload, String expected) {
        JsonNode aud = payload.get("aud");
        if (aud == null) {
            return false;
        }
        if (aud.isArray()) {
            for (JsonNode item : aud) {
                if (expected.equals(item.asText())) {
                    return true;
                }
            }
            return false;
        }
        return expected.equals(aud.asText());
    }

    private static String readTextClaim(JsonNode payload, String name) {
        JsonNode node = payload.get(name);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asText();
    }
}
