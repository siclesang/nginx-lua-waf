	-- nginx 内部跳转 不做处理
	if  ngx.req.is_internal()  then
		return
	end

	-- get X-Forwarded-For ,为空判断为直接访问机器，不做处理
	local xfw=ngx.var.http_x_forwarded_for
	if  xfw==nil then
		xfw=ngx.var.remote_addr
		--return
	end

	-- 速率 reqtotal_time_per/time_per (r/s) 
	-- nginx 配置文件中定义
	--     set $interval 4;
	--     set $reqs_interval 3
	local time_per = tonumber(ngx.var.interval)  or 1
	local reqtotal_time_per = tonumber(ngx.var.reqs_interval) or 15
	
	-- 判断其中的ip 是否合法
	if not isLegalIp(xfw) then
		ngx.exit(403)	
	end
	
	-- 是否在静态黑名单或者共享内存黑名单中 ,ip 在黑名单的过期时间 init.lua 中 ipBlockedTime 定义
	-- 有需要再开启
	if isBlocked(xfw) then
		ngx.exit(403)
	end

	-- 是否超速
	if ipLimit(xfw,time_per,reqtotal_time_per) then
		ngx.exit(403)		
	end
