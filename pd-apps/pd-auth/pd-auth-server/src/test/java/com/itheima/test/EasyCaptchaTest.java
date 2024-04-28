package com.itheima.test;

import com.wf.captcha.ChineseCaptcha;
import com.wf.captcha.base.Captcha;

import java.io.File;
import java.io.FileOutputStream;

public class EasyCaptchaTest {
    public static void main(String[] args) throws Exception{
        // 中文验证码
        Captcha captcha = new ChineseCaptcha();

        // 获取本次生成的验证码
        String code = captcha.text();
        System.out.println(code);

        // 生成图片
        captcha.out(new FileOutputStream(new File("D:\\test.png")));
    }
}
