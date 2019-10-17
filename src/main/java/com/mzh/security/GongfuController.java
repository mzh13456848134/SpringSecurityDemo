package com.mzh.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class GongfuController {
	
	//同时具有“PM - 项目经理”角色权限和“user:add”权限
	@PreAuthorize("hasRole('PM - 项目经理') AND hasAuthority('user:add')")
	@GetMapping("/level1/{path}")
	public String leve1Page(@PathVariable("path")String path){
		return "/level1/"+path;
	}
	
	//只要有“GL - 组长”或者“SE - 软件工程师”角色权限
	@PreAuthorize("hasAnyRole('GL - 组长','SE - 软件工程师')")
	@GetMapping("/level2/{path}")
	public String leve2Page(@PathVariable("path")String path){
		return "/level2/"+path;
	}
	//需要“user:add”或“user:delete”中得一个权限并且需要有“QA - 品质保证”角色权限
	@PreAuthorize("hasAnyAuthority('user:add','user:delete') AND hasRole('QA - 品质保证')")
	@GetMapping("/level3/{path}")
	public String leve3Page(@PathVariable("path")String path){
		return "/level3/"+path;
	}

}
