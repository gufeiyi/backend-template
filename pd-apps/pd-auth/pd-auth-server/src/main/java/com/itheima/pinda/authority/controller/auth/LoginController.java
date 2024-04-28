package com.itheima.pinda.authority.controller.auth;


import com.itheima.pinda.authority.biz.service.auth.ValidateCodeService;
import com.itheima.pinda.authority.biz.service.auth.impl.AuthManager;
import com.itheima.pinda.authority.dto.auth.LoginDTO;
import com.itheima.pinda.authority.dto.auth.LoginParamDTO;
import com.itheima.pinda.base.BaseController;
import com.itheima.pinda.base.R;
import com.itheima.pinda.log.annotation.SysLog;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录（认证）控制器
 */
@RestController
@RequestMapping("/anno")
@Api(value = "LoginController", tags = "登录控制器")
public class LoginController extends BaseController {

    @Autowired
    private ValidateCodeService validateCodeService;

    @Autowired
    private AuthManager authManager;

    // 为前端系统生成验证码
    @GetMapping(value = "/captcha", produces = "image/png")
    @ApiOperation(value = "获取验证码",notes = "获取验证码")
    @SysLog("生成验证码")
    public void captcha(@RequestParam(value = "key") String key, HttpServletResponse response) throws IOException {
        validateCodeService.create(key, response);
    }

    // 登录认证
    @PostMapping(value = "/login")
    @ApiOperation(value = "登录认证",notes = "登录认证")
    @SysLog("登录")
    public R<LoginDTO> login(@Validated @RequestBody LoginParamDTO loginParam) {
        boolean check = validateCodeService.check(loginParam.getKey(), loginParam.getCode());
        if (check) {
            // 校验通过，执行具体的登录认证逻辑
            R<LoginDTO> R = authManager.login(loginParam.getAccount(), loginParam.getPassword());
            return R;
        }
        // 校验不通过
        return this.success(null);
    }

    // 校验验证码
    @PostMapping(value = "/check")
    @ApiOperation(value = "校验验证码",notes = "校验验证码")
    public boolean check(@RequestBody LoginParamDTO loginParam) {
        return validateCodeService.check(loginParam.getKey(), loginParam.getCode());
    }
}
