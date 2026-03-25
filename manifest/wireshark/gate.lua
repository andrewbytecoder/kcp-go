-- SIPKCP/PSIPKCP protocol dissector plugin
-- @author: chengqianjie 
-- @data: 2023.4.17
-- @version: V1.0


local PsipSipkcp_proto_name = "SIPKCP_PSIPKCP"
local PsipSipkcp_proto_desc = "SIPKCP_PSIPKCP Protolcol"
local PsipSipkcp_proto = Proto(PsipSipkcp_proto_name, PsipSipkcp_proto_desc)
local PsipSipkcp_port = {14000, 15999}

local sipkcp_proto_name = "SIPKCP"
local sipkcp_proto_desc = "SIPKCP Protolcol"
local sipkcp_proto = Proto(sipkcp_proto_name, sipkcp_proto_desc)

local ProtocolInfo = ""


sipkcp_proto.fields.debug_number     = ProtoField.int32(PsipSipkcp_proto_name.. ".debug_uint32", "DEBUG_NUMBER")
sipkcp_proto.fields.debug_string     = ProtoField.string(PsipSipkcp_proto_name .. ".debug_string", "DEBUG_STRING")
sipkcp_proto.fields.debug_error     = ProtoField.string(PsipSipkcp_proto_name .. ".debug_error", "DEBUG_ERROR")
sipkcp_proto.fields.debug_warning     = ProtoField.string(PsipSipkcp_proto_name .. ".debug_warn", "DEBUG_WARNING")

--messageType
local MessageType_array = {
	[0x000] = "RPC",
	[0x001] = "MQ"
}


-- decoding			
base64 = {}
local encodeStd='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
-- decoding
function base64.dec(data)
	data = string.gsub(data, '[^'..encodeStd..'=]', '')
	return (data:gsub('.', function(x)
		if (x == '=') then return '' end
		local r,f='',(encodeStd:find(x)-1)
		for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
		return r;
	end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
		if (#x ~= 8) then return '' end
		local c=0
		for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
			return string.char(c)
	end))
end

function insertNewlines(str)
	local result = ""
	local num = 80
	for i=1, #str, num do
		if i + num >= #str then
			result = result .. string.sub(str, i, i + num -1)
		else
			result = result .. string.sub(str, i, i + num -1) .. "\r\n\t"	
		end 
		
	end
	return result
end


function hexString(str)
	local hexStr = ""
	local len = string.len(str)
	local num = 16

	for i = 1, len, 2 do
		hexStr = hexStr .. string.sub(str, i, i+1) .. " "
		if (i - 1) % num == 0 then
			hexStr = hexStr .. " "
		end
	end

	return hexStr
end

function tabBufNumLittle(tab, offset, length)
	local number = 0
	for i = 0, length - 1 do
		number = tab[offset + i] * (256^(length - i - 1)) + number
	end

	return number
end

function tabBufNumBig(tab, offset, length)
	local number = 0
	for i = length - 1, 0, -1 do
		number = tab[offset + i] * (256^(i)) + number
	end

	return number
end


function tabBufHEXNumLittleString(tab, offset, length)
	local number = ""
	for i = 0, length - 1 do
		if i == length - 1 then
			number ="0x" .. number .. string.format("%02X", tab[offset + i] )
		else
			number = number .. string.format("%02X", tab[offset + i] )
		end
		
	end

	return number
end


function tabBufHEXNumBigString(tab, offset, length)
	local number = ""
	for i = length - 1, 0, -1 do
		if tab[offset + i] == nil then
			break
		end
		if i == 0 then
			number ="0x".. number ..string.format("%02X", tab[offset + i] ) 
		else
			number = number .. string.format("%02X", tab[offset + i] )
		end
		
	end

	return number
end


function tabBufStr(tab, offset, length, subtree)
	local str = tostring(tab[offset]) 
	for i = 1, length - 1 do
		str = str..tab[offset + i]
	end

	return str
end

function tabBufIpv4Little(tab, offset, length, subtree)
	local str = tostring(tab[offset])
	for i = 1, length - 1 do
		str = str.."."..tostring(tab[offset + i])
	end

	return str
end

function tabBufIpv4Big(tab, offset, length, subtree)
	local str = tostring(tab[offset + length - 1])
	for i = length - 2, 0, -1 do
		str = str.."."..tostring(tab[offset + i])
	end

	return str
end


function tabBufIpv6(tab, offset, length, subtree)
	local str = tostring(tab[offset])
	for i = 1, length - 1 do
		str = str..":"..tostring(tab[offset + i])
	end

	return str
end


function airtonumber(air)
	local number=tonumber(air)
	local np=296+math.floor(number/2^15)
	local fin=0;
	local p3in=0;
	if((number-0x100001)%0x8000<0x3C29)
	then
		fin=math.floor(((number-0x100001)%0x8000)/700)+20
		p3in=math.floor(((number-0x100001)%0x8000)%700)+200
	else
		fin=math.floor(((number-0x103C29)%0x8000)/350)+42
		p3in=math.floor(((number-0x103C29)%0x8000)%350)+200
	end
	return tostring(np)..tostring(fin)..tostring(p3in)
end


function string.split(s, delim)
	if type(delim) ~= "string" or string.len(delim) <= 0 then
		return nil
	end

	local start = 1
	local t = {}
	while true do
	local pos = string.find (s, delim, start, true) -- plain find
		if not pos then
			break
		end
		table.insert (t, string.sub (s, start, pos - 1))
		start = pos + string.len (delim)
	end
	table.insert (t, string.sub (s, start))

	return t
end

function string.split1(s, delim)
	if type(delim) ~= "string" or string.len(delim) <= 0 then
		return nil
	end

	local start = 1
	local t = {}
	while true do
		local pos = string.find (s, delim, start, true) -- plain find
		if not pos then
			break
		end
		--table.insert (arry, string.sub (s, start, pos - 1))
		table.insert (t, {string.sub (s, start, pos - 1), start - 1, pos - 1})
		start = pos + string.len (delim)
	end
	table.insert (t, {string.sub (s, start), start - 1, -1})

	return t
end


function string.trim(s)   
	return (string.gsub(s, "^%s*(.-)%s*$", "%1"))  
end  

RequestLine={};
MessageHeader={};

sipkcp_proto.fields.HeaderVia = ProtoField.string(PsipSipkcp_proto_name .. ".HeaderVia", "HeaderVia")

function MessageHeader.dissector(buf, pinfo, treeitem)
	local offset = 0
	local tmpTable = string.split1(buf(offset):string(),"\r\n");

	for i = 1, #(tmpTable) do  
		local tempTree = treeitem:add(sipkcp_proto, buf(offset, string.len(tmpTable[i][1])), tmpTable[i][1])
		
		offset = offset + string.len(tmpTable[i][1])
	end
	
end

MessageBody={};

function MessageBody.Analyze(msgBody)
	return string.split(msgBody,"\r\n");
end

local function ip_addr_dissector(buf, pinfo, treeitem)
	local offset = 0
	local ip_len = 4
	local ip = tostring(buf(ip_len - 1, 1):uint())
	for i = 1, 3 do
		ip = ip.."."..tostring(buf(ip_len -i - 1 , 1):uint())
	end
	
	local port = tostring(buf(4, 2):le_uint())
	
	return ip..":"..port
end



local function ip_dissector(buf, pinfo, treeitem)
	local offset = 0
	local ip_len = 4
	local ip = tostring(buf(ip_len - 1, 1):uint())
	for i = 1, 3 do
		ip = ip.."."..tostring(buf(ip_len -i - 1 , 1):uint())
	end
	
	return ip
end

--sipkcp
--addr
sipkcp_proto.fields.flag = ProtoField.string(PsipSipkcp_proto_name .. ".flag", "Flag")
sipkcp_proto.fields.dstaddr = ProtoField.string(PsipSipkcp_proto_name .. ".dstaddr", "DstAddr")
sipkcp_proto.fields.dstport = ProtoField.uint16(PsipSipkcp_proto_name .. ".dstport", "DstPort", base.DEC)
sipkcp_proto.fields.nataddr = ProtoField.string(PsipSipkcp_proto_name .. ".nataddr", "NatAddr")
sipkcp_proto.fields.natport = ProtoField.uint16(PsipSipkcp_proto_name .. ".natport", "NatPort", base.DEC)
sipkcp_proto.fields.srcaddr = ProtoField.string(PsipSipkcp_proto_name .. ".srcaddr", "SrcAddr")
sipkcp_proto.fields.srcport = ProtoField.uint16(PsipSipkcp_proto_name .. ".srcport", "SrcPort", base.DEC)

	-- kcp
sipkcp_proto.fields.sid = ProtoField.string(PsipSipkcp_proto_name .. ".sid", "sid")
sipkcp_proto.fields.conversation = ProtoField.string(PsipSipkcp_proto_name .. ".conversation", "conversation")


local cmd_array = 
{
	[81] = "PSH",
	[82] = "ACK",
	[83] = "ASK",
	[84] = "TELL",
	[85] = "RST",
	[86] = "HB",
	[87] = "SYNC",
	[88] = "SYNC ACK",
}
sipkcp_proto.fields.cmd = ProtoField.uint8(PsipSipkcp_proto_name .. ".cmd", "cmd", base.DEC, cmd_array)
sipkcp_proto.fields.frg = ProtoField.uint16(PsipSipkcp_proto_name .. ".frg", "frg", base.DEC)
sipkcp_proto.fields.wnd = ProtoField.uint16(PsipSipkcp_proto_name .. ".wnd", "wnd", base.DEC)
sipkcp_proto.fields.ts  = ProtoField.uint32(PsipSipkcp_proto_name .. ".ts", "ts", base.DEC)
sipkcp_proto.fields.sn  = ProtoField.uint32(PsipSipkcp_proto_name .. ".sn", "sn", base.DEC)
sipkcp_proto.fields.una = ProtoField.uint32(PsipSipkcp_proto_name .. ".una", "una", base.DEC)
--reserved 64bit
sipkcp_proto.fields.reserved = ProtoField.string(PsipSipkcp_proto_name .. ".reserved", "reserved")
sipkcp_proto.fields.len = ProtoField.uint32(PsipSipkcp_proto_name .. ".len", "len")
sipkcp_proto.fields.data = ProtoField.string(PsipSipkcp_proto_name .. ".DATA", "DATA")
sipkcp_proto.fields.DataHex     = ProtoField.string("SIPKCP" .. ".DataHex", "DATA_HEX")
sipkcp_proto.fields.DataStr     = ProtoField.string("SIPKCP" .. ".DataStr", "DATA_STR")

function MessageBody.dissector(buf, pinfo, treeitem, ParentTree)
	local offset = 0
	treeitem:add_le(sipkcp_proto.fields.debug_string, buf(offset))

	--链接类型,中转的网闸地址和真是目的地址以及源地址 20字节
	local addrTree = treeitem:add(sipkcp_proto, buf(offset, 20), "ADDR")
	addrTree:add_le(sipkcp_proto.fields.flag, buf(offset, 2))
	offset = offset + 2
	addrTree:add_le(sipkcp_proto.fields.dstaddr, buf(offset, 4), ip_dissector(buf(offset, 4), pinfo, addrTree))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.dstport, buf(offset, 2))
	offset = offset + 2

	addrTree:add_le(sipkcp_proto.fields.nataddr, buf(offset, 4), ip_dissector(buf(offset, 4), pinfo, addrTree))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.natport, buf(offset, 2))
	offset = offset + 2

	addrTree:add_le(sipkcp_proto.fields.srcaddr, buf(offset, 4), ip_dissector(buf(offset, 4), pinfo, addrTree))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.srcport, buf(offset, 2))
	offset = offset + 2
	
	--KCP解析
	local kcp_len = 41
	local data_size = buf(offset):len()
	local conv = tostring(buf(8, 4):le_uint()) 
			conv = "conversation: "..conv.."("..string.format("0x%08x", conv)..")"

	-- kcp header
	local subtree = treeitem:add(sipkcp_proto, buf(offset, kcp_len), "KCP")

	subtree:add_le(sipkcp_proto.fields.sid, buf(offset, 8))
	offset = offset + 8
	subtree:add_le(buf(offset, 4), conv)
	offset = offset + 4
	subtree:add_le(sipkcp_proto.fields.cmd, buf(offset, 1))
	offset = offset + 1
	subtree:add_le(sipkcp_proto.fields.frg, buf(offset, 2))
	offset = offset + 2
	subtree:add_le(sipkcp_proto.fields.wnd, buf(offset, 2))
	offset = offset + 2
	subtree:add_le(sipkcp_proto.fields.ts, buf(offset, 4))
	offset = offset + 4
	subtree:add_le(sipkcp_proto.fields.sn, buf(offset, 4))
	offset = offset + 4
	subtree:add_le(sipkcp_proto.fields.una, buf(offset, 4))
	offset = offset + 4
	------------------------------------
	--reserved 预留
	subtree:add_le(sipkcp_proto.fields.reserved, buf(offset, 8))
	offset = offset + 8
	
	local data_len = buf(offset, 4):le_int()
	subtree:add_le(sipkcp_proto.fields.len, buf(offset, 4))
	offset = offset + 4
	
	
	if data_len ~= 0 then
		tmpTable = string.split1(buf(offset, data_len):string(),"\r\n")
		for  i = 1, #(tmpTable) do 
			if tmpTable[i][3] == -1 then 
				treeitem:add(sipkcp_proto.fields.data, buf(offset + tmpTable[i][2], string.len(tmpTable[i][1])), tmpTable[i][1])
			else
				treeitem:add(sipkcp_proto.fields.data, buf(offset+ tmpTable[i][2], string.len(tmpTable[i][1])), tmpTable[i][1])
			end			
		end
	end	
end

function base64ToBytes(decodeData)
	local bytesData = {}
	bytesData[0] = string.byte(decodeData, 1)
	for i = 1,  string.len(decodeData)+1 do
		bytesData[i] = string.byte(decodeData, i + 1)
	end
	return bytesData
end

function BytesToString(bytesData, dataStart, dataLen)

	local stringData = {}
	stringData = string.char(bytesData[dataStart])

	for i = 1,  dataLen - 1 do
			stringData = stringData .. string.char(bytesData[dataStart + i])
	end

	return stringData
end

function MessageBody.Base64_dataBody_dissector(offset, treeitem, bytesData, data_len)
	local Index = 0
	local textNum = 160
	local hexNum = 32
	local I = 0
	local log = ""
	local data = ""
	--json格式化
	-- local json = require "dkjson"
	-- for i = 0,  data_len - 1 do
	-- 	if bytesData[offset + i] == nil then
	--  		--log = string.format("\r\nWARNING:  Data totals [%d]bytes, \r\n\tthis body include [%d]bytes, \r\n\tthere are [%d]bytes left that are not included", data_len, i - 1,  data_len - i + 1)
	-- 		--..string.format(" hexIndex[%d], StrIndex:[%d]", hexIndex, StrIndex) 
			
	-- 		break
	-- 	end
	-- Index = Index + 1	
	-- end 
	-- data = BytesToString(bytesData, offset, Index)
	-- local json_val = json.decode(data)
	-- Index = 0
	

	-- if json_val ~= nil then
	-- 	-- 存在 JSON 数据，将其格式化后添加到协议树中
	-- 	local formatted_json = json.encode(json_val, {indent=true})
	-- 	treeitem:add_le(sipkcp_proto.fields.debug_string, formatted_json):set_text(formatted_json)
	-- end


	local textData = "DATA TEXT:"
	treeitem:add_le(textData):set_text(textData)
	--text 显示
	for i = 0,  data_len - 1 do
		if bytesData[offset + i] == nil then
			log = string.format("\r\nWARNING:  Data totals [%d]bytes, \r\n\tthis body include [%d]bytes, \r\n\tthere are [%d]bytes left that are not included", data_len, i - 1,  data_len - i + 1)
			--..string.format(" hexIndex[%d], StrIndex:[%d]", hexIndex, StrIndex) 
			
			break
		end
		
		if Index >= textNum then
			data = "\t"..insertNewlines(BytesToString(bytesData, offset + i - Index, Index)) 
			treeitem:add(textData):set_text(data)
			Index = 0
		else
			Index = Index + 1	
		end
		I = i
	end
	I = I + 1

	if Index ~= 0	 then
		data = "\t"..insertNewlines(BytesToString(bytesData, offset + I - Index, Index)) 
		treeitem:add(textData):set_text(data)
	end
	Index = 0

	local hexData = "DATA HEX:"
	treeitem:add(hexData):set_text("\r\n".. hexData)
	--hex 显示
	for i = 0,  data_len - 1 do
		if bytesData[offset + i] == nil then
			log = string.format("\r\nWARNING:  Data totals [%d]bytes, \r\n\tthis body include [%d]bytes, \r\n\tthere are [%d]bytes left that are not included", data_len, i - 1,  data_len - i + 1)
			--..string.format(" hexIndex[%d], StrIndex:[%d]", hexIndex, StrIndex) 
			
			break
		end
		
		if Index >= hexNum then
			data = "\t"..hexString(tabBufHEXNumLittleString(bytesData, offset + i - Index, Index)) 
			treeitem:add(hexData):set_text(data)
			Index = 0
		else
			Index = Index + 1	
		end

		I = i
	end
	I = I + 1
	
	if Index ~= 0	 then
		data = "\t"..hexString(tabBufHEXNumLittleString(bytesData, offset + I - Index, Index))
		treeitem:add(hexData):set_text(data)
	end

	if log ~= ""  then
		treeitem:add(sipkcp_proto.fields.debug_warning,  log):set_text(log)
	end
end

--mq msg
sipkcp_proto.fields.mqMagic = ProtoField.uint16(PsipSipkcp_proto_name .. ".Magic", "Magic", base.DEC)
sipkcp_proto.fields.mqVersion = ProtoField.uint16(PsipSipkcp_proto_name .. ".Version", "Version", base.DEC)
sipkcp_proto.fields.mqHeadLen = ProtoField.uint8(PsipSipkcp_proto_name .. ".HeadLen", "HeadLen", base.DEC)
sipkcp_proto.fields.mqPriority = ProtoField.uint8(PsipSipkcp_proto_name .. ".Priority", "Priority", base.DEC)
sipkcp_proto.fields.mqReserved1 = ProtoField.uint16(PsipSipkcp_proto_name .. ".Reserved1", "Reserved1", base.DEC)
sipkcp_proto.fields.mqSrcName = ProtoField.string(PsipSipkcp_proto_name .. ".SrcName", "SrcName")
sipkcp_proto.fields.mqSrcID  = ProtoField.string(PsipSipkcp_proto_name .. ".SrcID", "SrcID")--uint64
sipkcp_proto.fields.mqBalanceId  = ProtoField.string(PsipSipkcp_proto_name .. ".BalanceId", "BalanceId")--uint64
sipkcp_proto.fields.mqBodyLen = ProtoField.uint32(PsipSipkcp_proto_name .. ".BodyLen", "BodyLen", base.DEC)
sipkcp_proto.fields.mqMsgType = ProtoField.uint32(PsipSipkcp_proto_name .. ".MsgType", "MsgType", base.DEC)
sipkcp_proto.fields.mqMsgSeq = ProtoField.uint32(PsipSipkcp_proto_name .. ".MsgSeq", "MsgSeq", base.DEC)
sipkcp_proto.fields.mqTraceFlag = ProtoField.uint8(PsipSipkcp_proto_name .. ".TraceFlag", "TraceFlag", base.DEC)
sipkcp_proto.fields.mqTraceCtxLen = ProtoField.uint8(PsipSipkcp_proto_name .. ".TraceCtxLen", "TraceCtxLen", base.DEC)
sipkcp_proto.fields.mqTraceContext = ProtoField.string(PsipSipkcp_proto_name .. ".TraceContext", "TraceContext")
--reserved 16bit
sipkcp_proto.fields.mqReserved = ProtoField.string(PsipSipkcp_proto_name .. ".Reserved", "Reserved")
sipkcp_proto.fields.mqBody = ProtoField.string(PsipSipkcp_proto_name .. ".Body", "Body")

function MessageBody.Base64_mqdata_dissector( buf, offset, treeitem, bytesData, data_len)
	--treeitem:add_le(sipkcp_proto.fields.debug_number, tabBufNumLittle(bytesData, offset + 2, 2))
	if data_len < 56 or  tabBufNumLittle(bytesData, offset + 2, 2) ~= 1 then
		local datatree = treeitem:add(sipkcp_proto, buf(0), "Body")
		--treeitem:add_le(sipkcp_proto.fields.debug_number,  mqBodyLen)
		MessageBody.Base64_dataBody_dissector(offset, datatree, bytesData, data_len)
		--treeitem:add_le("Body", BytesToString(bytesData, offset, data_len))
		return
	end

	treeitem:add_le(sipkcp_proto.fields.mqMagic, tabBufNumLittle(bytesData, offset, 2))
	offset = offset + 2
	treeitem:add_le(sipkcp_proto.fields.mqVersion, tabBufNumLittle(bytesData, offset, 2))
	offset = offset + 2

	local mqHeadLen = tabBufNumLittle(bytesData, offset, 1)
	treeitem:add_le(sipkcp_proto.fields.mqHeadLen, tabBufNumLittle(bytesData, offset, 1))
	offset = offset + 1
	treeitem:add_le(sipkcp_proto.fields.mqPriority, tabBufNumLittle(bytesData, offset, 1))
	offset = offset + 1
	treeitem:add_le(sipkcp_proto.fields.mqReserved1, tabBufNumLittle(bytesData, offset, 2))
	offset = offset + 2
	treeitem:add_le(sipkcp_proto.fields.mqSrcName, BytesToString(bytesData, offset, 16))
	offset = offset + 16
	treeitem:add_le(sipkcp_proto.fields.mqSrcID, string.format("%.0f", tabBufNumLittle(bytesData, offset, 8)))
	offset = offset + 8
	treeitem:add_le(sipkcp_proto.fields.mqBalanceId, string.format("%.0f", tabBufNumLittle(bytesData, offset, 8)))
	offset = offset + 8

	local mqBodyLen = tabBufNumLittle(bytesData, offset, 4)
	treeitem:add_le(sipkcp_proto.fields.mqBodyLen, tabBufNumLittle(bytesData, offset, 4))
	offset = offset + 4
	treeitem:add_le(sipkcp_proto.fields.mqMsgType, tabBufNumLittle(bytesData, offset, 4))
	offset = offset + 4
	treeitem:add_le(sipkcp_proto.fields.mqMsgSeq, tabBufNumLittle(bytesData, offset, 4))
	offset = offset + 4
	treeitem:add_le(sipkcp_proto.fields.mqTraceFlag, tabBufNumLittle(bytesData, offset, 1))
	offset = offset + 1
	
	local mqTraceCtxLen = tabBufNumLittle(bytesData, offset, 1)
	treeitem:add_le(sipkcp_proto.fields.mqTraceCtxLen, tabBufNumLittle(bytesData, offset, 1))
	offset = offset + 1
	treeitem:add_le(sipkcp_proto.fields.mqTraceContext, tabBufNumLittle(bytesData, offset, mqTraceCtxLen))
	offset = offset + mqTraceCtxLen
	treeitem:add_le(sipkcp_proto.fields.mqReserved, tabBufHEXNumLittleString(bytesData, offset, 2))
	offset = offset + 2

	local datatree = treeitem:add(sipkcp_proto, buf(0), "Body")
	--treeitem:add_le(sipkcp_proto.fields.debug_number,  mqBodyLen)
	MessageBody.Base64_dataBody_dissector(offset, datatree, bytesData, mqBodyLen)

end

function MessageBody.Base64_dissector(buf, pinfo, treeitem, ParentTree)
	local offset = 0
	--treeitem:add_le(sipkcp_proto.fields.debug_string, buf(offset))
	local data = base64.dec(buf(offset):string())
	local bytesData = base64ToBytes(data)
	--treeitem:add_le(sipkcp_proto.fields.debug_number, string.len(data))
	--treeitem:add_le(sipkcp_proto.fields.debug_number, #bytesData)
	if #bytesData < 19 then
		return
	end

	--链接类型,中转的网闸地址和真是目的地址以及源地址 20字节
	local addrTree = treeitem:add(sipkcp_proto, buf(0), "ADDR")
	local messageType = MessageType_array[tabBufNumBig(bytesData, offset, 2)]
	--addrTree:add_le(sipkcp_proto.fields.flag, tabBufNumBig(bytesData, offset, 2))
	addrTree:add_le(sipkcp_proto.fields.flag, tabBufHEXNumBigString(bytesData, offset, 2))
	offset = offset + 2
	addrTree:add_le(sipkcp_proto.fields.dstaddr, tabBufIpv4Big(bytesData,offset, 4))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.dstport, tabBufNumBig(bytesData, offset, 2))
	offset = offset + 2

	addrTree:add_le(sipkcp_proto.fields.nataddr, tabBufIpv4Big(bytesData,offset, 4))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.natport, tabBufNumBig(bytesData, offset, 2))
	offset = offset + 2

	addrTree:add_le(sipkcp_proto.fields.srcaddr, tabBufIpv4Big(bytesData,offset, 4))
	offset = offset + 4
	addrTree:add_le(sipkcp_proto.fields.srcport, tabBufNumBig(bytesData, offset, 2))
	offset = offset + 2
	
	if #bytesData < 60 then
		return
	end

	--KCP解析
	local kcp_len = 41
	local data_size = buf(offset):len()
	local conv = tabBufNumBig(bytesData, offset + 8, 4)
			conv = conv.."("..tabBufHEXNumBigString(bytesData, offset + 8, 4)..")"

	-- kcp header
	local subtree = treeitem:add(sipkcp_proto, buf(0), "KCP")
	subtree:add(sipkcp_proto.fields.sid, string.format("%.0f", tabBufNumBig(bytesData, offset, 8)))
	offset = offset + 8
	subtree:add_le(sipkcp_proto.fields.conversation, conv)
	offset = offset + 4
	
	local Cmd = cmd_array[tabBufNumBig(bytesData, offset, 1)]
	subtree:add_le(sipkcp_proto.fields.cmd, tabBufNumBig(bytesData, offset, 1))
	ProtocolInfo = ProtocolInfo.."("..Cmd..")"
	pinfo.cols.info = ProtocolInfo
	offset = offset + 1
	subtree:add_le(sipkcp_proto.fields.frg, tabBufNumBig(bytesData, offset, 2))
	offset = offset + 2
	subtree:add_le(sipkcp_proto.fields.wnd, tabBufNumBig(bytesData, offset, 2))
	offset = offset + 2
	subtree:add_le(sipkcp_proto.fields.ts, tabBufNumBig(bytesData, offset, 4))
	offset = offset + 4
	subtree:add_le(sipkcp_proto.fields.sn, tabBufNumBig(bytesData, offset, 4))
	offset = offset + 4
	subtree:add_le(sipkcp_proto.fields.una, tabBufNumBig(bytesData, offset, 4))
	offset = offset + 4
	------------------------------------
	--reserved 预留
	subtree:add_le(sipkcp_proto.fields.reserved, string.format("%.0f", tabBufNumBig(bytesData, offset, 8)))
	offset = offset + 8
	
	local data_len = tabBufNumBig(bytesData, offset, 4)
	subtree:add_le(sipkcp_proto.fields.len, tabBufNumBig(bytesData, offset, 4))
	offset = offset + 4
	
	--subtree:add_le(sipkcp_proto.fields.debug_number, data_len)
	if data_len ~= 0 then
		local datatree = subtree:add(sipkcp_proto, buf(0), "Data")
		if messageType == "RPC" then
			MessageBody.Base64_dataBody_dissector(offset, datatree, bytesData, data_len)
		elseif messageType == "MQ" then
			MessageBody.Base64_mqdata_dissector(buf, offset, datatree, bytesData, data_len)
		end
		
		
		--subtree:add_le(sipkcp_proto.fields.debug_number, string.len(BytesToString(bytesData, offset, data_len)))
		--subtree:add_le(sipkcp_proto.fields.data, BytesToString(bytesData, offset, data_len))
	end
end

ProtolAnalyze={}

function ProtolAnalyze.GetRequestLine(data)
	local index = string.find(data,"\r\n")
	return 0, index - 1
end

function ProtolAnalyze.GetMessageHeader(data)
	local indexheaderstart = string.find(data,"\r\n")+2
	local indexheaderend = string.find(data,"\r\n\r\n",indexheaderstart)
	if indexheaderend == nil then
		indexheaderend = string.find(data,"\r\n\r",indexheaderstart)
	end
	return indexheaderstart - 1, indexheaderend - indexheaderstart
end

function ProtolAnalyze.GetMessageBody(data)
	local indexbodystart = string.find(data,"\r\n\r\n")
	if indexbodystart == nil then
		indexbodystart = string.find(data,"\r\n\r")
	end
	return indexbodystart + 3
end

StatuCode={};

									
sipkcp_proto.fields["Requset-Line"] = ProtoField.string(PsipSipkcp_proto_name..".RequsetLine", "Requset-Line", base.NONE)
sipkcp_proto.fields["MessageHeader"] = ProtoField.string(PsipSipkcp_proto_name..".MessageHeader", "Message Header", base.NONE)
sipkcp_proto.fields["MessageBody"] = ProtoField.string(PsipSipkcp_proto_name..".MessageBody", "Message Body", base.NONE)
sipkcp_proto.fields["Method"] = ProtoField.string(PsipSipkcp_proto_name..".Method", "Method", base.NONE)
sipkcp_proto.fields["RequestURIHostPart"] = ProtoField.string(PsipSipkcp_proto_name..".RequestURIHostPart", "Request-URI Host Part", base.NONE)
sipkcp_proto.fields["RequestURIHostPort"] = ProtoField.string(PsipSipkcp_proto_name..".RequestURIHostPort", "Request-URI Host Port", base.NONE)


--解请求头
function RequestLine.dissector(buf, pinfo, treeitem)
	local offset = 0
	local data = buf(offset):string()
	local spaceindex = string.find(data, " ")
	local method = buf(offset, spaceindex - 1):string()
	treeitem:add(sipkcp_proto.fields["Method"], buf(offset, spaceindex - 1), method)
	offset = offset +  spaceindex
	
	local schemindex1 = string.find(buf(offset):string(),"@")

	spaceindex = string.find(buf(offset):string(), " ")
	--local schem = buf(offset, schemindex1 - 1):string()

	local URItree = treeitem:add(sipkcp_proto, buf(offset, spaceindex - 1), "Request-URI:"..buf(offset, spaceindex - 1):string())
	ProtocolInfo = "Request: "..method.." "..buf(offset, spaceindex - 1):string()
	pinfo.cols.info = ProtocolInfo
	offset = offset +  schemindex1
	local schemindex2 = string.find(buf(offset):string(),":")

	URItree:add(sipkcp_proto.fields["RequestURIHostPart"], buf(offset, schemindex2 - 1))
	offset = offset +  schemindex2

	spaceindex = string.find(buf(offset):string(), " ")
	URItree:add(sipkcp_proto.fields["RequestURIHostPort"], buf(offset, spaceindex -1))
end

function CheckSipKcp(data)
	local space = string.find(data," ")
	if space == nil or space > string.find(data,"\r\n") or 
		string.sub(data, space + 1 , space + 1 + 2) ~= "sip"then
		return false	
	end
	
	return true
end

function sipkcp_proto.dissector(tvb, pinfo, treeitem)     
	-- if pinfo.dst_port <= sipkcp_start_port and pinfo.dst_port >= sipkcp_end_port  then
	-- 	return
	-- end

	if not CheckSipKcp(tvb:range(0,tvb:len()):string()) then
		--protocol_psipkcp.dissector(tvb, pinfo, treeitem) 
	else 
		local offset = 0
		local tvb_len = tvb:len()
		local data=tvb:range(offset,tvb_len):string()
		local root_tree = treeitem:add(sipkcp_proto, tvb:range(offset))
		-- 设置一些 UI 上面的信息
		pinfo.cols.protocol:set("SIPKCP")
		pinfo.cols.info:set("SIPKCP Protocol")

		--获取requestline
		local requestLineStart, requestLineLen = ProtolAnalyze.GetRequestLine(data)
		local RequestLineTree = root_tree:add(sipkcp_proto, tvb(requestLineStart, requestLineLen), 
								"Requset-Line".."("..tvb(requestLineStart, requestLineLen):string()..")")

		RequestLine.dissector(tvb(requestLineStart, requestLineLen):tvb(), pinfo, RequestLineTree)
		offset = offset + requestLineLen

		
		--获取messageheader
		local msgHeaderStart, msgHeaderLen=ProtolAnalyze.GetMessageHeader(data);
		
		--获取messagebody
		local msgBodyStart = ProtolAnalyze.GetMessageBody(data);
		
		
		local MessageHeaderTree = root_tree:add(sipkcp_proto, tvb(msgHeaderStart, msgHeaderLen), "Message Header") 
		MessageHeader.dissector(tvb(msgHeaderStart, msgHeaderLen):tvb(), pinfo, MessageHeaderTree)
		
		if(msgBody~="")
		then
			local MessageBodyTree = root_tree:add(sipkcp_proto, tvb(msgBodyStart), "Message Body")

			--MessageBody.dissector(tvb(msgBodyStart):tvb(), pinfo, MessageBodyTree, root_tree)
			MessageBody.Base64_dissector(tvb(msgBodyStart):tvb(), pinfo, MessageBodyTree, root_tree)
			
		end
	end
end





--[[************************************************************************************************
										↑sipkcp↑
										↓psipkcp↓
************************************************************************************************]]--


local psipkcp_proto_name = "PSIPKCP"
local psipkcp_proto_desc = "PSIPKCP Protolcol"
local psipkcp_Proto = Proto(psipkcp_proto_name, psipkcp_proto_desc)
local psipkcp_proto_info = ""

psipkcp_Proto.fields.debug_number     = ProtoField.int32(PsipSipkcp_proto_name .. ".debug_uint32", "DEBUG_NUMBER")
psipkcp_Proto.fields.debug_string     = ProtoField.string(PsipSipkcp_proto_name .. ".debug_string", "DEBUG_STRING")


function airtonumber(air)
	local number=tonumber(air)
	local np=296+math.floor(number/2^15)
	local fin=0;
	local p3in=0;
	if((number-0x100001)%0x8000<0x3C29)
	then
		fin=math.floor(((number-0x100001)%0x8000)/700)+20
		p3in=math.floor(((number-0x100001)%0x8000)%700)+200
	else
		fin=math.floor(((number-0x103C29)%0x8000)/350)+42
		p3in=math.floor(((number-0x103C29)%0x8000)%350)+200
	end
	return tostring(np)..tostring(fin)..tostring(p3in)
end

function BufHEXNumLittleString(tvb, offset, length)
	local number = ""
	for i = 0, length - 1 do
		if i == length - 1 then
			number ="0x" .. number .. string.format("%02X", tvb(offset + i, 1):uint())
		else
			number = number .. string.format("%02X", tvb(offset + i, 1):uint())
		end
		
	end

	return number
end

function string.split(s, delim)
	if type(delim) ~= "string" or string.len(delim) <= 0 then
		return nil
	end

	local start = 1
	local t = {}
	while true do
	local pos = string.find (s, delim, start, true) -- plain find
		if not pos then
		  break
		end
		table.insert (t, string.sub (s, start, pos - 1))
		start = pos + string.len (delim)
	end
	table.insert (t, string.sub (s, start))

	return t
end

function string.split1(s, delim)
	if type(delim) ~= "string" or string.len(delim) <= 0 then
		return nil
	end

	local start = 1
	local t = {}
	while true do
		local pos = string.find (s, delim, start, true) -- plain find
		if not pos then
		  break
		end
		--table.insert (arry, string.sub (s, start, pos - 1))
		table.insert (t, {string.sub (s, start, pos - 1), start - 1, pos - 1})
		start = pos + string.len (delim)
	end
	table.insert (t, {string.sub (s, start), start - 1, -1})

	return t
end


function string.trim(s)   
	return (string.gsub(s, "^%s*(.-)%s*$", "%1"))  
end  

PSipKcpRequestLine={};
PSipKcpRequestLine.MethodTable={};
PSipKcpRequestLine.MethodTable["I"]="INVITE";
PSipKcpRequestLine.MethodTable["A"]="ACK";
PSipKcpRequestLine.MethodTable["O"]="OPTIONS";
PSipKcpRequestLine.MethodTable["T"]="INFO";
PSipKcpRequestLine.MethodTable["B"]="BYE";
PSipKcpRequestLine.MethodTable["C"]="CANCEL";
PSipKcpRequestLine.MethodTable["R"]="REGISTER";
PSipKcpRequestLine.MethodTable["Q"]="SUBSCRIBE";
PSipKcpRequestLine.MethodTable["U"]="UPDATE";
PSipKcpRequestLine.MethodTable["M"]="MESSAGE";
PSipKcpRequestLine.MethodTable["P"]="PUBLISH";
PSipKcpRequestLine.MethodTable["N"]="NOTIFY";
PSipKcpRequestLine.MethodTable["F"]="REFER";
PSipKcpRequestLine.MethodTable["H"]="PREPARE";
PSipKcpRequestLine.MethodTable["E"]="RESTORE";
--[[
function PSipKcpRequestLine.CreateProtoField()
	local tmpProtopsipkcp_Fields = {};
	for key, value in pairs(PSipKcpRequestLine.MethodTable) 
	do 
		table.insert(tmpProtopsipkcp_Fields,ProtoField.string("PSIP.Method", value, base.NONE));
	end
	return tmpProtopsipkcp_Fields;
end
--]]
PSipKcpRequestLine.SchemTable={}
PSipKcpRequestLine.SchemTable["p"]= "PDT-PRIVATE-USER";
PSipKcpRequestLine.SchemTable["g"]= "PDT-GROUP-USER";

PSipKcpMessageHeader={};
PSipKcpMessageHeader.Table={};
PSipKcpMessageHeader.Table["Z"]="Accept"
PSipKcpMessageHeader.Table["A"]="Authorization"
PSipKcpMessageHeader.Table["i"]="Call-ID"
PSipKcpMessageHeader.Table["m"]="Contact"
PSipKcpMessageHeader.Table["l"]="Content-Length"
PSipKcpMessageHeader.Table["c"]="Content-Type"
PSipKcpMessageHeader.Table["C"]="Call-Info"
PSipKcpMessageHeader.Table["Q"]="CSeq"
PSipKcpMessageHeader.Table["o"]="Event"
PSipKcpMessageHeader.Table["X"]="Expires"
PSipKcpMessageHeader.Table["f"]="From"
PSipKcpMessageHeader.Table["Y"]="Handover-Number"
PSipKcpMessageHeader.Table["H"]="Max-Forwards"
PSipKcpMessageHeader.Table["MX"]="Min-Expires"
PSipKcpMessageHeader.Table["N"]="P-Access-Network-Info"
PSipKcpMessageHeader.Table["TI"]="P-Asserted-Temporary-Identity"
PSipKcpMessageHeader.Table["p"]="Priority"
PSipKcpMessageHeader.Table["f"]="From"
PSipKcpMessageHeader.Table["R"]="Route"
PSipKcpMessageHeader.Table["SR"]="Service-Route"
PSipKcpMessageHeader.Table["U"]="Subscription-State"
PSipKcpMessageHeader.Table["t"]="To"
PSipKcpMessageHeader.Table["to"]="To"
PSipKcpMessageHeader.Table["ua"]="User-Agent"
PSipKcpMessageHeader.Table["v"]="Via"
PSipKcpMessageHeader.Table["W"]="WWW-Authenticate"

PSipKcpMessageHeader.EventTable={};
PSipKcpMessageHeader.EventTable["p"]="presence"
PSipKcpMessageHeader.EventTable["st"]="stun"
PSipKcpMessageHeader.EventTable["kl"]="kill"
PSipKcpMessageHeader.EventTable["rv"]="revive"
PSipKcpMessageHeader.EventTable["dl"]="discreet-listening"
PSipKcpMessageHeader.EventTable["i"]="get-dia-id"
PSipKcpMessageHeader.EventTable["gg"]="get-gps"
PSipKcpMessageHeader.EventTable["gc"]="get-channelno"
PSipKcpMessageHeader.EventTable["h"]="get-handover-num"
PSipKcpMessageHeader.EventTable["hb"]="heartbeat"
PSipKcpMessageHeader.EventTable["ds"]="delete-subscriber"
PSipKcpMessageHeader.EventTable["ug"]="update-group"
PSipKcpMessageHeader.EventTable["ga"]="regroup-subscriber-add"
PSipKcpMessageHeader.EventTable["gd"]="regroup-subscriber-del"
PSipKcpMessageHeader.EventTable["ag"]="attachment-group"
PSipKcpMessageHeader.EventTable["rs"]="resync"-- ���к�ͬ��
PSipKcpMessageHeader.EventTable["aa"]="active-auth"
PSipKcpMessageHeader.EventTable["ss"]="state-sub"
PSipKcpMessageHeader.EventTable["mn"]="monitor"
PSipKcpMessageHeader.EventTable["ms"]="merge-group-set"
PSipKcpMessageHeader.EventTable["md"]="merge-group-del"
PSipKcpMessageHeader.EventTable["mg"]="merge-group-get"

PSipKcpMessageHeader.MediaMasterType={};
PSipKcpMessageHeader.MediaMasterType["a"]="application"
PSipKcpMessageHeader.MediaMasterType["t"]="text"

PSipKcpMessageHeader.MediaSubType={};
PSipKcpMessageHeader.MediaSubType["s"]="SDP"
PSipKcpMessageHeader.MediaSubType["p"]="PLAIN"
PSipKcpMessageHeader.MediaSubType["z"]="STATUS"
PSipKcpMessageHeader.MediaSubType["n"]="NMEA"
PSipKcpMessageHeader.MediaSubType["bn"]="BNMEA"
PSipKcpMessageHeader.MediaSubType["b"]="BIN"
PSipKcpMessageHeader.MediaSubType["m"]="MAP"
	
function PSipKcpMessageHeader.dissector(buf, pinfo, treeitem)
	local offset = 0
	local tmpTable=string.split1(buf(offset):string(),"\r\n");
	-- demo key="o" value 
		
	for i=1, #(tmpTable) do    
		--treeitem:add(psipkcp_Proto.fields.debug_string, tmpTable[i][1])	
		local index= string.find(tmpTable[i][1],":")
		local key = string.sub(tmpTable[i][1],1, index-1)
		local value = string.sub(tmpTable[i][1], index+1, string.len(tmpTable[i][1]))
		if(key =="o")
		then
			value = PSipKcpMessageHeader.EventTable[string.trim(value)]
		end
		
		if tmpTable[i][3] == -1 then 
			treeitem:add(psipkcp_Proto.fields["Header"..key], buf(tmpTable[i][2]), value)
		else
			treeitem:add(psipkcp_Proto.fields["Header"..key], buf(tmpTable[i][2], tmpTable[i][3] - tmpTable[i][2]), value)
		end
	end  
end

function PSipKcpMessageHeader.dissector1(buf, pinfo, treeitem)
	local offset = 0
	local tmpTable=string.split(buf(offset):string(),"\r\n");
	-- demo key="o" value 
	local tmpRTable={};
		
	for i=1, #(tmpTable) do      
		local index= string.find(tmpTable[i],":");
		
		local key = string.sub(tmpTable[i],1,index-1)
		local value = string.sub(tmpTable[i],index+1,string.len(tmpTable[i]))
		local instructionValue=nil
		if(key=="o")
		then
			instructionValue=PSipKcpMessageHeader.EventTable[string.trim(value)]
		end
	
		if(instructionValue~=nil)
		then
			tmpRTable[key]=instructionValue
		else
			tmpRTable[key]=value
		end
	end  

	return tmpRTable;
end

PSipKcpMessageBody={};
PSipKcpMessageBody.Table={};

function PSipKcpMessageBody.Analyze(msgBody)
	return string.split(msgBody,"\r\n");
end

--addr
local link_type_array = 
{
	[00] = "PPC",
	[01] = "DATA",
}
psipkcp_Proto.fields.linkType = ProtoField.uint16(PsipSipkcp_proto_name .. ".linkType", "LinkType", base.DEC, link_type_array)
psipkcp_Proto.fields.realAddr = ProtoField.string(PsipSipkcp_proto_name .. ".realAddr", "RealAddr")
psipkcp_Proto.fields.networkGatewayAddr = ProtoField.string(PsipSipkcp_proto_name .. ".networkGatewayAddr", "NetworkGatewayAddr")
psipkcp_Proto.fields.localAddr = ProtoField.string(PsipSipkcp_proto_name .. ".localAddr", "LocalAddr")

local function ip_addr_dissector(buf, pinfo, treeitem)
	local offset = 0
	local ip_len = 4
	local ip = tostring(buf(ip_len - 1, 1):uint())
	for i = 1, 3 do
		ip = ip.."."..tostring(buf(ip_len -i - 1 , 1):uint())
	end
	
	local port = tostring(buf(4, 2):le_uint())
	
	return ip..":"..port
end


 -- kcp
psipkcp_Proto.fields.appid = ProtoField.uint64(PsipSipkcp_proto_name .. ".appid", "appid", base.DEC)
psipkcp_Proto.fields.conversation = ProtoField.uint32(PsipSipkcp_proto_name .. ".conversation", "conversation", base.DEC)


psipkcp_Proto.fields.cmd = ProtoField.uint8(PsipSipkcp_proto_name .. ".cmd", "cmd", base.DEC, cmd_array)
psipkcp_Proto.fields.frg = ProtoField.uint8(PsipSipkcp_proto_name .. ".frg", "frg", base.DEC)
psipkcp_Proto.fields.wnd = ProtoField.uint16(PsipSipkcp_proto_name .. ".wnd", "wnd", base.DEC)
psipkcp_Proto.fields.ts  = ProtoField.uint32(PsipSipkcp_proto_name .. ".ts", "ts", base.DEC)
psipkcp_Proto.fields.sn  = ProtoField.uint32(PsipSipkcp_proto_name .. ".sn", "sn", base.DEC)
psipkcp_Proto.fields.una = ProtoField.uint32(PsipSipkcp_proto_name .. ".una", "una", base.DEC)
psipkcp_Proto.fields.version = ProtoField.uint16(PsipSipkcp_proto_name .. ".version", "version", base.DEC)
--reserved 64bit
psipkcp_Proto.fields.reserved = ProtoField.uint16(PsipSipkcp_proto_name .. ".reserved", "reserved", base.DEC)
psipkcp_Proto.fields.reserved2 = ProtoField.uint32(PsipSipkcp_proto_name .. ".reserved2", "reserved2", base.DEC)
psipkcp_Proto.fields.len = ProtoField.uint32(PsipSipkcp_proto_name .. ".len", "len")

psipkcp_Proto.fields.data = ProtoField.string(PsipSipkcp_proto_name .. ".DATA", "DATA")

function PSipKcpMessageBody.dissector(buf, pinfo, treeitem, ParentTree)
	local offset = 0
	
	--��������,��ת����բ��ַ������Ŀ�ĵ�ַ�Լ�Դ��ַ 20�ֽ�
	local addrTree = treeitem:add(psipkcp_Proto, buf(offset, 20), "ADDR")
	addrTree:add_le(psipkcp_Proto.fields.linkType, buf(offset, 2))
	offset = offset + 2
	addrTree:add_le(psipkcp_Proto.fields.realAddr, buf(offset, 6), ip_addr_dissector(buf(offset, 6), pinfo, addrTree))
	offset = offset + 6
	addrTree:add_le(psipkcp_Proto.fields.networkGatewayAddr, buf(offset, 6), ip_addr_dissector(buf(offset, 6), pinfo, addrTree))
	offset = offset + 6
	addrTree:add_le(psipkcp_Proto.fields.localAddr, buf(offset, 6), ip_addr_dissector(buf(offset, 6), pinfo, addrTree))
	offset = offset + 6
	
	--KCP����
	local kcpversion = buf(offset +28, 2):le_uint()
	local kcp_len = 0
	local data_size = buf(offset):len()
	local conv = tostring(buf(8, 4):le_uint()) 
		  conv = "conversation: "..conv.."("..string.format("0x%08x", conv)..")"
	-- kcp header
	if (kcpversion == 0)then
		if data_size < 40 then 
			return
		end 
		kcp_len = 40 
	else
		kcp_len = 36
	end
	local subtree = treeitem:add(psipkcp_Proto, buf(offset, kcp_len), "KCP")

	subtree:add_le(psipkcp_Proto.fields.appid, buf(offset, 8))
	offset = offset + 8
	subtree:add_le(buf(offset, 4), conv)
	offset = offset + 4
	
	local cmd = buf(offset, 1):uint()
	pinfo.cols.info = psipkcp_proto_desc.."["..cmd_array[cmd].."]"
	subtree:add_le(psipkcp_Proto.fields.cmd, buf(offset, 1))
	offset = offset + 1
	subtree:add_le(psipkcp_Proto.fields.frg, buf(offset, 2))
	offset = offset + 2
	subtree:add_le(psipkcp_Proto.fields.wnd, buf(offset, 2))
	offset = offset + 2
	subtree:add_le(psipkcp_Proto.fields.ts, buf(offset, 4))
	offset = offset + 4
	subtree:add_le(psipkcp_Proto.fields.sn, buf(offset, 4))
	offset = offset + 4
	subtree:add_le(psipkcp_Proto.fields.una, buf(offset, 4))
	offset = offset + 4
	----------------------------------
	subtree:add_le(psipkcp_Proto.fields.version, buf(offset, 2))
	offset = offset + 2
	------------------------------------
	--reserved Ԥ��
	subtree:add_le(psipkcp_Proto.fields.reserved, buf(offset, 2))
	offset = offset + 2
	
	if (kcpversion == 0)then
		subtree:add_le(psipkcp_Proto.fields.reserved2, buf(offset, 4))
		offset = offset + 4
	end	
	
	local data_len = buf(offset, 4):le_int()
	subtree:add_le(psipkcp_Proto.fields.len, buf(offset, 4))
	offset = offset + 4
	
	
	if data_len ~= 0 then
		tmpTable = string.split1(buf(offset):string(),"\r\n\r\n")
		for  i = 1, #(tmpTable)-1 do 
			if tmpTable[i][3] == -1 then 
				treeitem:add(psipkcp_Proto.fields.data, buf(offset + tmpTable[i][2], string.len(tmpTable[i][1])), tmpTable[i][1])
				treeitem:add(psipkcp_Proto.fields.data, BufHEXNumLittleString(buf(offset + tmpTable[i][2], string.len(tmpTable[i][1])),0,string.len(tmpTable[i][1])))
			else
				treeitem:add(psipkcp_Proto.fields.data, buf(offset+ tmpTable[i][2], string.len(tmpTable[i][1])), tmpTable[i][1])
				treeitem:add(psipkcp_Proto.fields.data, BufHEXNumLittleString(buf(offset + tmpTable[i][2], string.len(tmpTable[i][1])),0,string.len(tmpTable[i][1])))
			end			
		end
	end
	
	
end

PSipKcpAnalyze={}

function PSipKcpAnalyze.IsRequest(data)
	local tmpstr = string.sub(data,1,3);
	local firstch = string.sub(data,1,1);
	if(tmpstr=="SIP" or (firstch>="0" and firstch<="6"))
	then
	return false;
	end
	return true;
end

function PSipKcpAnalyze.GetRequestLine(data)
	local index = string.find(data,"\r\n")
	return 0, index - 1
end

function PSipKcpAnalyze.GetStatuLine(data)
	local index = string.find(data,"\r\n")
	return 0, index - 1
end

function PSipKcpAnalyze.GetPSipKcpMessageHeader(data)
	local indexheaderstart = string.find(data,"\r\n")+2
	local indexheaderend = string.find(data,"\r\n\r\n",indexheaderstart)
	if indexheaderend == nil then
		indexheaderend = string.find(data,"\r\n\r",indexheaderstart)
	end
	return indexheaderstart - 1, indexheaderend - indexheaderstart
end

function PSipKcpAnalyze.GetPSipKcpMessageBody(data)
	local indexbodystart = string.find(data,"\r\n\r\n")
	if indexbodystart == nil then
		indexbodystart = string.find(data,"\r\n\r")
	end
	return indexbodystart + 4 + 3
end

PSipKcpStatuCode={};
PSipKcpStatuCode["100"]="Trying"
PSipKcpStatuCode["180"]="Ringing"
PSipKcpStatuCode["181"]="call being forwarder"
PSipKcpStatuCode["182"]="queue"
PSipKcpStatuCode["183"]="session progress"
PSipKcpStatuCode["200"]="OK"
PSipKcpStatuCode["202"]=""
PSipKcpStatuCode["300"]="multiple"
PSipKcpStatuCode["301"]="moved permanently"
PSipKcpStatuCode["302"]="moved temporaily"
PSipKcpStatuCode["305"]="use proxy"
PSipKcpStatuCode["380"]="alternative service"
PSipKcpStatuCode["400"]="bad request"
PSipKcpStatuCode["401"]="unauthorized"
PSipKcpStatuCode["402"]="payment required"
PSipKcpStatuCode["403"]="forbidden"
PSipKcpStatuCode["300"]="multiple"
PSipKcpStatuCode["404"]="not found"
PSipKcpStatuCode["405"]="method no allowed"
PSipKcpStatuCode["406"]="not acceptable"
PSipKcpStatuCode["407"]="proxy authentication required"
PSipKcpStatuCode["408"]="request timeout"	
PSipKcpStatuCode["410"]="gone"	
PSipKcpStatuCode["413"]="request entity too large"
PSipKcpStatuCode["414"]="request-url too long"	
PSipKcpStatuCode["415"]="unsupported media type"	
PSipKcpStatuCode["416"]="unsupported url scheme"	
PSipKcpStatuCode["420"]="bad extension"	
PSipKcpStatuCode["421"]="extension required"	
PSipKcpStatuCode["423"]="interval too brief"	
PSipKcpStatuCode["480"]="temporarily unavailable"	
PSipKcpStatuCode["481"]="call/transaction does not exist"	
PSipKcpStatuCode["482"]="loop detected"	
PSipKcpStatuCode["483"]="too many hops"	
PSipKcpStatuCode["484"]="address incomplete"	
PSipKcpStatuCode["485"]="ambiguous"	
PSipKcpStatuCode["486"]="busy here"	
PSipKcpStatuCode["487"]="request terminated"	
PSipKcpStatuCode["488"]="not acceptable here"	
PSipKcpStatuCode["491"]="request pending"	
PSipKcpStatuCode["493"]="undecipherable"	
PSipKcpStatuCode["500"]="server internal error"	
PSipKcpStatuCode["501"]="not implemented"	
PSipKcpStatuCode["502"]="bad gateway"	
PSipKcpStatuCode["504"]="server time-out"	
PSipKcpStatuCode["505"]="version not supported"	
PSipKcpStatuCode["513"]="message too large"	
PSipKcpStatuCode["600"]="busy everywhere"	
PSipKcpStatuCode["603"]="decline"	
PSipKcpStatuCode["604"]="does not exist anywhere"	
PSipKcpStatuCode["606"]="not acceptable"	
									

psipkcp_Proto.fields["RequsetLine"] = ProtoField.string(PsipSipkcp_proto_name..".RequsetLine", "Requset-Line", base.NONE)
psipkcp_Proto.fields["StatuLine"] = ProtoField.string(PsipSipkcp_proto_name..".StatuLine", "StatuLine", base.NONE)
psipkcp_Proto.fields["PSipKcpMessageHeader"] = ProtoField.string(PsipSipkcp_proto_name..".PSipKcpMessageHeader", "Message Header", base.NONE)
psipkcp_Proto.fields["PSipKcpMessageBody"] = ProtoField.string(PsipSipkcp_proto_name..".PSipKcpMessageBody", "Message Body", base.NONE)
psipkcp_Proto.fields["Method"] = ProtoField.string(PsipSipkcp_proto_name..".Method", "Method", base.NONE)
psipkcp_Proto.fields["Schem"] = ProtoField.string(PsipSipkcp_proto_name..".Schem", "Schem", base.NONE)
psipkcp_Proto.fields["TargetNumber"] = ProtoField.string(PsipSipkcp_proto_name..".TargetNumber", "TargetNumber", base.NONE)
psipkcp_Proto.fields["RequestURI"] = ProtoField.string(PsipSipkcp_proto_name..".RequestURI", "Request-URI", base.NONE)
psipkcp_Proto.fields["NULL"] = ProtoField.string(PsipSipkcp_proto_name..".NULL", " ", base.NONE)

for key , value in pairs (PSipKcpMessageHeader.Table) do
	psipkcp_Proto.fields["Header"..key] = ProtoField.string(PsipSipkcp_proto_name..".Header", value, base.NONE)
end

--������ͷ
function PSipKcpRequestLine.dissector(buf, pinfo, treeitem)
	local offset = 0
	local data = buf(offset):string()
	local spaceindex = string.find(data, " ")
	local method = PSipKcpRequestLine.MethodTable[buf(offset, spaceindex - 1):string()]
	treeitem:add(psipkcp_Proto.fields["Method"], buf(offset, spaceindex - 1), method)
	offset = offset +  spaceindex
	
	local schemindex = string.find(buf(offset):string(),":",1)
	local schem = buf(offset, schemindex - 1):string()
	if(schem == 's')
	then
		treeitem:add(psipkcp_Proto.fields["RequestURI"], buf(offset):string())
		psipkcp_proto_desc = "Request: "..method.." "..buf(offset):string()
	else
		treeitem:add(psipkcp_Proto.fields["Schem"], buf(offset, schemindex - 1), PSipKcpRequestLine.SchemTable[schem])
		offset = offset +  schemindex
		local targetnumber = buf(offset):string()
		treeitem:add(psipkcp_Proto.fields["TargetNumber"], buf(offset), airtonumber(targetnumber))
		psipkcp_proto_desc ="Request: "..method.." "..PSipKcpRequestLine.SchemTable[schem].." "..airtonumber(targetnumber)
		
	end
	pinfo.cols.info = psipkcp_proto_desc
end

function CheckPSipKcp(data)
	local space = string.find(data," ")
	if space == nil or space > string.find(data,"\r\n") or 
	PSipKcpRequestLine.MethodTable[string.sub(data, 1 , space - 1)] == nil then
		return false	
	end
	
	return true
end


function psipkcp_Proto.dissector(tvb, pinfo, treeitem)
	local offset = 0
	local tvb_len = tvb:len()
	
	local data=tvb:range(offset,tvb_len):string()

	pinfo.cols.protocol:set(psipkcp_proto_name)
	pinfo.cols.info:set(psipkcp_proto_desc)
			
	local root_tree = treeitem:add(psipkcp_Proto, tvb:range(offset))
	   
	if(PSipKcpAnalyze.IsRequest(data))
	--����
	then
	--��ȡrequestline
		local requestLineStart, requestLineLen = PSipKcpAnalyze.GetRequestLine(data)
		local RequestLineTree = root_tree:add(psipkcp_Proto, tvb(requestLineStart, requestLineLen), "RequsetLine".."("..tvb(requestLineStart, requestLineLen):string()..")")
		PSipKcpRequestLine.dissector(tvb(requestLineStart, requestLineLen):tvb(), pinfo, RequestLineTree)
		offset = offset + requestLineLen
	else
	--��Ӧ
		local statuLineStart, statuLineLen=PSipKcpAnalyze.GetStatuLine(data)
		local statu = tvb(offset, statuLineLen):string()
		pinfo.cols.info = "Status: "..statu.." "..PSipKcpStatuCode[statu];
		root_tree:add(psipkcp_Proto.fields["StatuLine"], tvb(offset, statuLineLen), statu)
		offset = offset + statuLineLen
	end
	
	--��ȡmessageheader
	local msgHeaderStart, msgHeaderLen=PSipKcpAnalyze.GetPSipKcpMessageHeader(data);
	
	--��ȡmessagebody
	local msgBodyStart=PSipKcpAnalyze.GetPSipKcpMessageBody(data);
	
	
	local PSipKcpMessageHeaderTree = root_tree:add(psipkcp_Proto, tvb(msgHeaderStart, msgHeaderLen), "MessageHeader") 
	PSipKcpMessageHeader.dissector(tvb(msgHeaderStart, msgHeaderLen):tvb(), pinfo, PSipKcpMessageHeaderTree)
	
	if(msgBody~="")
	then
		local PSipKcpMessageBodyTree=root_tree:add(psipkcp_Proto, tvb(msgBodyStart), "MessageBody")		
		PSipKcpMessageBody.dissector(tvb(msgBodyStart):tvb(), pinfo, PSipKcpMessageBodyTree, root_tree)
		
	end
	
end

function PsipSipkcp_proto.dissector(tvb, pinfo, treeitem)
	local offset = 0
	local tvb_len = tvb:len()
	
	local Proto
	local data=tvb:range(offset,tvb_len):string()
	if not CheckSipKcp(data) then	
		if CheckPSipKcp(data) then
			Proto = psipkcp_Proto
		else
			return
		end
	else
		Proto = sipkcp_proto
	end

	Proto.dissector(tvb, pinfo, treeitem)
end

for port = PsipSipkcp_port[1], PsipSipkcp_port[2] do
	DissectorTable.get("udp.port"):add(port, PsipSipkcp_proto)
end
