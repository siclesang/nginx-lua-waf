#!/bin/env lua

---------------------------------------config-----------------------------------
----
whiteList={
"10.201.0.0/16",
"10.212.0.0./16",
"124.74.42.36/30",
"180.166.184.96/29",
"140.207.97.96/29"
}

--静态黑名单  与 共享内存中的黑名单(ip_blocked=blocked)有别 
blackList={
"1.1.1.1/32"
}

-- 共享内存 ip_blocked过期时间
ipBlockedTime=60


-------------------------------------function------------------------------------
-- 简单判断 ip 是否合法
function isLegalIp(ip)
        if string.match(ip,"%d+%.%d+%.%d+%.%d+") ~=nil then
                local   o1,o2,o3,o4 = string.match(ip,"(%d+)%.(%d+)%.(%d+)%.(%d+)")
                o1=tonumber(o1)
                o2=tonumber(o2)
                o3=tonumber(o3)
                o4=tonumber(o4)
                if ((o1>0 and o1<=255) and (o2>=0 and o2<=255) and (o3>=0 and o3<=255) and (o4>=0 and o4<=255) ) then
                        return true
                else
                        ngx.log(ngx.ERR,"ip:"..ip.." is invalid")
                        return false
                end
        else
                ngx.log(ngx.ERR,"ip:"..ip.." is invalid")
                return false
        end
end


-- 取商 取余
function modi(n,m)
	return n%m==0 and n/m or (n-1)/m , n%m
end


-- 将数字 转化为 10 字符串
function intTo10(n)
	if n==0  then 
		return n 
	else
		local s=""
		local z,y=modi(n,2)
		s=y..s
		while  z >= 2 
		do
		z,y=modi(z,2)
		s=y..s 
		end
		if z==1 then s="1"..s end
		return s
	end	
end

-- 获取网络号 用于判断是否是同一子网
function subnet10(ip,amask)
	local	o1,o2,o3,o4 = string.match(ip,"(%d+)%.(%d+)%.(%d+)%.(%d+)")
	o1=tonumber(o1)
	o2=tonumber(o2)
	o3=tonumber(o3)
	o4=tonumber(o4)
	
	local	ipbytes=string.format("%08d",intTo10(o1))..string.format("%08d",intTo10(o2))..string.format("%08d",intTo10(o3))..string.format("%08d",intTo10(o4))
	if amask then
		return	string.sub(ipbytes,1,tonumber(amask))
	else
	
		return	string.sub(ipbytes,1,32)
	end
end

-- 查找是否在白名单中，与函数isInList(table,ip)作用相似  
function isWhiteIp(ip)
        for k,v in ipairs(whiteList) do
		local ipOfList,mask=string.match(v,"(.*)%/(.*)")

		if  not ipOfList then     
                        ipOfList=v
                        mask=32
                end

		if subnet10(ip,mask)==subnet10(ipOfList,mask) then
                        return true
                end
        end
        return false
end


-- 查找ip是否在table中
function isInList(table,ip)
        for k,v in ipairs(table) do
		local ipOfList,mask=string.match(v,"(.*)%/(.*)")

                if  not ipOfList then
                        ipOfList=v
                        mask=32
                end

		if subnet10(ip,mask)==subnet10(ipOfList,mask) then
                        return true
                end
        end
        return false
end

--xff 头信息  除了白名单之外的ip，超速返回403 并将ip_blocked=blocked存入共享内存中
function ipLimit(xfw,time_per,reqtotal_time_per)
 
        local max_count=1 --max req count
        local max_count_ip="" --max req ip
        local dogs = ngx.shared.dogs

        for w in string.gmatch(xfw,"%d+%.%d+%.%d+%.%d+") do
                if not isInList(whiteList,w) then
                        --ngx.say(w)
                        local c,err=dogs:get(w)
                        if c == nil then
                                local ok, err=dogs:set(w,1,time_per)
                        else
                                local v, err=dogs:incr(w,1)
                                if v == nil then
                                        return false
                                end
                                if v > max_count then
                                        max_count=v
                                        max_count_ip=w
                                end
                        end
                end
        end

        --ngx.log(ngx.ERR,"ip :"..max_count_ip.." max count is "..max_count)
        --ngx.log(ngx.ERR,"event end")
        if max_count > reqtotal_time_per then
		local c,err=dogs:get(max_count_ip.."_blocked")
		if c == nil then 
			local ok, err=dogs:set(max_count_ip.."_blocked","blocked",ipBlockedTime)
                	ngx.log(ngx.ERR,max_count_ip.."_blocked:".."blocked")
		end
		ngx.log(ngx.ERR,"deny access  from xff "..max_count_ip)
                return true
		--ngx.exit(403)   
                --return ngx.redirect("http://www.feiniu.com",301)
        end
	
	return false

end

--查看是否在共享内存的ip是否blocked中
function isBlocked(ip)
	local dogs = ngx.shared.dogs

	for w in string.gmatch(ip,"%d+%.%d+%.%d+%.%d+") do
		--是否在静态黑名单
                if isInList(blackList,w) then
			ngx.log(ngx.ERR,"ip:"..w.." is in static blacklist")
                        return true
                end
		--是否在共享黑名单
		if not isInList(whiteList,w) then
		local v, err=dogs:get(w.."_blocked")
			if v=="blocked" then
				return true
			end
		end
	end
	
	return false
end





