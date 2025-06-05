package cn.keking.web.controller;

import cn.keking.config.ConfigConstants;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 *  页面跳转
 * @author yudian-it
 * @date 2017/12/27
 */
@Controller
public class IndexController {

    @GetMapping( "/index")
    public String go2Index(){
        // 检查是否启用首页
        if (ConfigConstants.getHomeEnabled() != null && !ConfigConstants.getHomeEnabled()) {
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND, "首页已被禁用");
        }
        return "/main/index";
    }

    @GetMapping( "/record")
    public String go2Record(){
        return "/main/record";
    }

    @GetMapping( "/sponsor")
    public String go2Sponsor(){
        return "/main/sponsor";
    }

    @GetMapping( "/integrated")
    public String go2Integrated(){
        return "/main/integrated";
    }

    @GetMapping( "/")
    public String root() {
        // 检查是否启用首页
        if (ConfigConstants.getHomeEnabled() != null && !ConfigConstants.getHomeEnabled()) {
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND, "首页已被禁用");
        }
        return "/main/index";
    }

}
