a nginx lua waf

1.防御 伪造 x-forwarded-for 攻击
2.设置黑白名单
3.log记录

-----------------file list-----------------
>init.lua  --黑白名单配置&函数
>limit.lua  --防御逻辑



-----------------nginx conf example---------

lua_shared_dict dogs 10m;
init_by_lua_file conf/conf.d/init.lua; 
lua_package_path '/home/webuser/www/module/?.lua;;';
server {
        listen       80;
        server_name  localhost;
	#以下2个参数如果不设置默认 15 requests/ 1 s
	#统计单位间隔(s)
	set $interval 60; 
	#单位时间请求阀值
	set $reqs_interval 3;
	
	access_by_lua_file conf/conf.d/limit.lua;
	lua_code_cache off;
	root /home/webuser/www/views;

    location / {
	index index.html;
	}

}

