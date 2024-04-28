package com.itheima.pinda.authority.biz.service.auth.impl;

import cn.hutool.crypto.digest.DigestUtil;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.itheima.pinda.auth.server.utils.JwtTokenServerUtils;
import com.itheima.pinda.auth.utils.JwtUserInfo;
import com.itheima.pinda.auth.utils.Token;
import com.itheima.pinda.authority.biz.service.auth.ResourceService;
import com.itheima.pinda.authority.biz.service.auth.UserService;
import com.itheima.pinda.authority.dto.auth.LoginDTO;
import com.itheima.pinda.authority.dto.auth.ResourceQueryDTO;
import com.itheima.pinda.authority.dto.auth.UserDTO;
import com.itheima.pinda.authority.entity.auth.Resource;
import com.itheima.pinda.authority.entity.auth.User;
import com.itheima.pinda.base.R;
import com.itheima.pinda.common.constant.CacheKey;
import com.itheima.pinda.dozer.DozerUtils;
import com.itheima.pinda.exception.code.ExceptionCode;
import lombok.extern.slf4j.Slf4j;
import net.oschina.j2cache.CacheChannel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 提供认证管理服务
 */
@Service
@Slf4j
public class AuthManager {

    @Autowired
    private UserService userService;

    @Autowired
    private DozerUtils dozerUtils;

    @Autowired
    private JwtTokenServerUtils jwtTokenServerUtils;

    @Autowired
    private ResourceService resourceService;

    @Autowired
    private CacheChannel cacheChannel;
    // 登录认证
    public R<LoginDTO> login(String account,String password) {
        // 校验账号，密码是否正确
        R<User> userR = check(account, password);
        Boolean isError = userR.getIsError();
        if (isError){
            return R.fail("认证失败");
        }

        // 为用户生成jwt令牌
        User user = userR.getData();
        Token token = generateToken(user);

        // 查询当前用户可以访问的资源权限
        List<Resource> userResources = resourceService.findVisibleResource(ResourceQueryDTO.builder().userId(user.getId()).build());
        log.info("当前用户可以访问的资源权限：{}",userResources);

        List<String> permissionList = null;
        if (userResources != null && userResources.size()>0){
            // 将用户对应的权限进行缓存（给前端使用）
            permissionList = userResources.stream().map(Resource::getCode).collect(Collectors.toList());

            // 将用户对应的权限进行缓存（给网关使用）
            List<String> visibleResource = userResources.stream().map((resource -> {
                return resource.getMethod() + resource.getUrl();
            })).collect(Collectors.toList());

            // 给网关使用的权限缓存到redis
            cacheChannel.set(CacheKey.USER_RESOURCE,user.getId().toString(),visibleResource);
        }

        // 封装返回结果
        LoginDTO loginDTO = LoginDTO.builder().
                user(dozerUtils.map(userR.getData(), UserDTO.class)).
                token(token).
                permissionsList(permissionList).
                build();
        return R.success(loginDTO);

    }

    // 检验用户名和密码是否合法，同时给密码加密
    public R<User> check(String account, String password){
        User user = userService.getOne(Wrappers.<User>lambdaQuery().eq(User::getAccount, account));

        // 将前端提交的密码进行md5加密
        String md5Hex = DigestUtil.md5Hex(password);
        if (user == null || !user.getPassword().equals(md5Hex)){
            // 认证失败
            return R.fail(ExceptionCode.JWT_USER_INVALID);
        }
        // 认证成功
        return R.success(user);

    }

    // 为当前登录用户生成对应的jwt令牌
    public Token generateToken(User user) {
        JwtUserInfo jwtUserInfo = new JwtUserInfo(user.getId(), user.getAccount(), user.getName(), user.getOrgId(), user.getStationId());
        Token token = jwtTokenServerUtils.generateUserToken(jwtUserInfo, null);
        return token;
    }
}
