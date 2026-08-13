package cn.keking.web.filter;

import cn.keking.config.PreviewAuthProperties;
import cn.keking.utils.RoadflowTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * 预览鉴权：仅登录用户（有效 roadflow-token）可访问预览接口及转换后的文件。
 */
public class RoadflowTokenAuthFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoadflowTokenAuthFilter.class);

    /**
     * 预览页依赖的静态资源，放行以便登录后正常渲染。
     */
    private static final List<String> STATIC_PREFIXES = Arrays.asList(
            "/js/", "/css/", "/images/", "/pdfjs/", "/bootstrap/", "/bootstrap-table/",
            "/drawio/", "/dcm/", "/xmind/", "/xlsx/", "/pptx/", "/ofd/", "/eml/",
            "/bpmn/", "/ckplayer/", "/xspreadsheet/", "/website/", "/excel/", "/error/"
    );

    private final PreviewAuthProperties previewAuthProperties;
    private final RoadflowTokenValidator roadflowTokenValidator;
    private String unauthorizedHtml;

    public RoadflowTokenAuthFilter(PreviewAuthProperties previewAuthProperties,
                                   RoadflowTokenValidator roadflowTokenValidator) {
        this.previewAuthProperties = previewAuthProperties;
        this.roadflowTokenValidator = roadflowTokenValidator;
    }

    @Override
    public void init(javax.servlet.FilterConfig filterConfig) {
        try {
            ClassPathResource resource = new ClassPathResource("static/error/401.html");
            byte[] bytes = FileCopyUtils.copyToByteArray(resource.getInputStream());
            this.unauthorizedHtml = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            this.unauthorizedHtml = "<html><body><h3>401 未登录或登录已失效，请重新登录后再预览文件</h3></body></html>";
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!previewAuthProperties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        if (!previewAuthProperties.isConfigured()) {
            LOGGER.error("preview.auth.enabled=true 但未配置 preview.auth.token-secret，拒绝预览请求");
            writeUnauthorized((HttpServletResponse) response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String servletPath = normalizePath(httpRequest.getServletPath());

        if (isStaticResource(servletPath)) {
            chain.doFilter(request, response);
            return;
        }

        String tokenName = previewAuthProperties.getTokenName();
        String token = resolveToken(httpRequest, tokenName);
        String userId = roadflowTokenValidator.validate(token);
        if (userId == null) {
            writeUnauthorized(httpResponse);
            return;
        }

        if (shouldRefreshCookie(httpRequest, tokenName, token)) {
            writeAuthCookie(httpResponse, tokenName, token);
        }
        chain.doFilter(request, response);
    }

    private static String normalizePath(String servletPath) {
        if (servletPath == null || servletPath.isEmpty()) {
            return "/";
        }
        return servletPath;
    }

    private static boolean isStaticResource(String servletPath) {
        if ("/favicon.ico".equals(servletPath)) {
            return true;
        }
        for (String prefix : STATIC_PREFIXES) {
            if (servletPath.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String resolveToken(HttpServletRequest request, String tokenName) {
        String headerToken = request.getHeader(tokenName);
        if (StringUtils.hasText(headerToken)) {
            return headerToken.trim();
        }
        String queryToken = request.getParameter(tokenName);
        if (StringUtils.hasText(queryToken)) {
            return queryToken.trim();
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (tokenName.equals(cookie.getName()) && StringUtils.hasText(cookie.getValue())) {
                    return cookie.getValue().trim();
                }
            }
        }
        return null;
    }

    /**
     * Header / Query 携带 token 时刷新 Cookie，供 pdf.js、静态 PDF 等后续请求使用。
     */
    private static boolean shouldRefreshCookie(HttpServletRequest request, String tokenName, String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }
        if (StringUtils.hasText(request.getHeader(tokenName))) {
            return true;
        }
        return StringUtils.hasText(request.getParameter(tokenName));
    }

    private void writeAuthCookie(HttpServletResponse response, String tokenName, String token) {
        Cookie cookie = new Cookie(tokenName, token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(previewAuthProperties.getCookieMaxAge());
        response.addCookie(cookie);
    }

    private void writeUnauthorized(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(unauthorizedHtml);
        response.getWriter().close();
    }

    @Override
    public void destroy() {
    }
}
