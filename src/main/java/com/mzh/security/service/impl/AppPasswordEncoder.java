package com.mzh.security.service.impl;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mzh.security.util.MD5Util;

@Service
public class AppPasswordEncoder implements PasswordEncoder{
	/**
	 * 密码加密算法
	 */
	@Override
	public String encode(CharSequence rawPassword) {
		String digest = MD5Util.digest(rawPassword.toString());
		return digest;
	}
	/**
	 * 比较登陆密码和数据库密码是否一致
	 *rawPassword 表示页面的明文喵喵
	 *encodedPassword  表示数据库的密文密码
	 */
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String digest = MD5Util.digest(rawPassword.toString());
		return digest.equals(encodedPassword);
	}

}
