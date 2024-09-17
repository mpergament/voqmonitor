-- Define the protocol name and table
local arista_voq = Proto("arista_voq", "Arista VoQ Monitor")

-- Define the fields for the protocol
local f_voq = ProtoField.string("VOQID", "VOQID")
local f_fwd_vsi = ProtoField.uint16("FWD_VSI", "FWD_VSI", base.INT)
arista_voq.fields = { f_voq, f_fwd_vsi }
-- Arista Registered Ethertype
local arista_ethertype = 0x1044
local etypetable = DissectorTable.get("ethertype")

-- Create a map from integer values to strings
local integer_to_string_map = {
    [74] = " inNullRoute (VOQID 74)",
}

-- Function to get a string representation from an integer value
function get_string_from_integer(value)
    return integer_to_string_map[value] or "Unknown"
end

-- Dissector for the Arista EtherType
function arista_voq.dissector(buf, packet, tree)
  -- look at subtype
  local offset = buf:len() - 32
  local pos=0
  -- check if it is a timestamp
  local next_type = buf(offset,2):uint()
  -- Get the dissector for that type
  local d = etypetable:get_dissector(next_type)

  -- Verify that Wireshark understands it
  if d then
   d:call(buf:range(pos):tvb(), packet, tree)
  else
   Dissector.get("ethertype"):call(buf:range(pos):tvb(),packet,tree)
  end

--   -- Set the protocol name in the Wireshark GUI
--   pinfo.cols.protocol = arista_voq.name
  local subtree = tree:add(arista_voq, buf(offset,32), "Arista VoQ Monitor")
  local voq_value = buf(offset+24, 1):uint()
  subtree:add(f_voq, get_string_from_integer(voq_value))
  subtree:add(f_fwd_vsi, buf(offset+15, 2))
end

etypetable:add(arista_ethertype, arista_voq)
