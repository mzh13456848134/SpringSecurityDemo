package com.mzh.security.service.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class AppUserDetailServiceImpl implements UserDetailsService{

	@Autowired
	JdbcTemplate jdbcTemplate;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String sql= "SELECT * FROM `t_admin` WHERE loginacct = ?";
		
		//1查询指定用户的信息
		Map<String, Object> adminMap = jdbcTemplate.queryForMap(sql, username);
		
		
		String roleSql = "SELECT t_role.id,`name` FROM t_role LEFT  JOIN t_admin_role ON t_role.id = t_admin_role.roleid WHERE t_admin_role.adminid = ?";
		
		//根据用户id查询所拥有的role
		List<Map<String, Object>> roleMap = jdbcTemplate.queryForList(roleSql, adminMap.get("id"));
		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		
		//用来存放后续需要查询角色的id
		String roleIds = "";
		for(Map<String, Object> map : roleMap) {
			String roleId = map.get("id").toString();
			authorities.add(new SimpleGrantedAuthority("ROLE_" + map.get("name").toString()));
			roleIds += roleId + ",";
		}
		
		String permissionSqlString = "SELECT `name` FROM t_permission LEFT JOIN t_role_permission ON t_permission.id = t_role_permission.permissionid  WHERE t_role_permission.roleid in (?)";
		
		//根据roleIds 一次性查询出所对应的权限
		List<Map<String, Object>> permissionMap= jdbcTemplate.queryForList(permissionSqlString, roleIds.substring(0,roleIds.length()-1));
		
		for(Map<String, Object> map : permissionMap) {
			authorities.add(new SimpleGrantedAuthority(map.get("name").toString()));
		}
		
		System.out.println("role" + roleMap.toString() + "permission" + permissionMap.toString());
		System.out.println(authorities);
		//2将查询到的用户封装到框架使用UserDetails里面
		return new User(adminMap.get("loginacct").toString(),adminMap.get("userpswd").toString(),authorities); 
				//AuthorityUtils.createAuthorityList("ADMIN","MANAGER","USER:ADD","USER:DELETE")); //认证权限暂时写死//以后直接从数据库查
	}

}
