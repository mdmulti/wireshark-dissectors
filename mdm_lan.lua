-- MDMLAN
-- MDMulti LAN Discovery Dissector for Wireshark.

mdmlan_protocol = Proto("MDMLAN",  "MDMulti LAN Discovery")

server = ProtoField.string("mdmlan.server", "Server")
proto_version = ProtoField.string("mdmlan.protoversion", "Protocol Version")
app = ProtoField.string("mdmlan.app", "Application Name")
ip = ProtoField.string("mdmlan.conn.ip", "Connection IP")
port = ProtoField.string("mdmlan.conn.port", "Connection Port")

ptype = ProtoField.string("mdmlan.type", "Packet Type")

mdmlan_protocol.fields = { server, proto_version, app, ip, port, ptype }

function mdmlan_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = mdmlan_protocol.name
  
  print("HAI")
  -- Loop over string until you reach the first /
  local server_length
  for i = 0, length - 1, 1 do
    if (buffer(i,1):string() == "/") then
		server_length = i 
		break
	end
  end
  
  local proto_version_length
  for i2 = server_length + 1, length - 1, 1 do
    if (buffer(i2,1):string() == "/") then
		proto_version_length = i2
		break
	end
  end
  
  local app_length
  for i3 = proto_version_length + 1, length - 1, 1 do
    if (buffer(i3,1):string() == "/") then
		app_length= i3
		break
	end
  end
  
  local ip_length
  for i4 = app_length + 1, length - 1, 1 do
    if (buffer(i4,1):string() == "/") then
		ip_length= i4
		break
	end
  end
  
  -- Find the packet type
  local ptype_value
  if (pinfo.dst_port == 29571) then
	ptype_value = "Multicast"
  elseif (pinfo.dst_port == 25816) then
	ptype_value = "Broadcast"
  else
	ptype_value = "Unknown"
  end

  local subtree = tree:add(mdmlan_protocol, buffer(), "MDMulti LAN Device")
  subtree:add_le(server, buffer(0, server_length))
  subtree:add_le(proto_version, buffer(server_length + 1, proto_version_length - server_length - 1))
  subtree:add_le(app, buffer(proto_version_length + 1, app_length - proto_version_length - 1))
  subtree:add_le(ip, buffer(app_length + 1, ip_length - app_length - 1))
  subtree:add_le(port, buffer(ip_length + 1))
  
  subtree:add_le(ptype, ptype_value)
  
  pinfo.cols.info:append("; " .. "[" .. ptype_value .. "] " .. buffer(proto_version_length + 1, app_length - proto_version_length - 1):string() .. "/" .. buffer(server_length + 1, proto_version_length - server_length - 1):string() .. " (" .. buffer(app_length + 1, ip_length - app_length - 1):string() .. ":" .. buffer(ip_length + 1):string() .. ")")
  
end

local udp_port = DissectorTable.get("udp.port")
-- Multicast Port 
udp_port:add(29571, mdmlan_protocol)
-- Broadcast Port
udp_port:add(25816, mdmlan_protocol)
