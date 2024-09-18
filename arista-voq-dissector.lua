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
    [64] = " inPortNotVlanMember (VOQID 64)",
    [65] = " inSaEqualsDa (VOQID 65)",
    [66] = " inSaMulticast (VOQID 66)",
    [67] = " inRpf (VOQID 67)",
    [68] = " inIpVersionError (VOQID 68)",
    [69] = " inIpv4ChecksumError (VOQID 69)",
    [70] = " inIpTtl0 (VOQID 70)",
    [71] = " inIpv6UnspecifiedDestination (VOQID 71)",
    [72] = " inIpv6MulticastSource (VOQID 72)",
    [73] = " inNoArp (VOQID 73)",
    [74] = " inNullRoute (VOQID 74)",
    [75] = " inArpCapacity (VOQID 75)",
    [76] = " inPbr (VOQID 76)",
    [77] = " outMtuTunnel (VOQID 77)",
    [78] = " inTunVxlan (VOQID 78)",
    [79] = " inElkError (VOQID 79)",
    [80] = " inSaNotFound (VOQID 80)",
    [81] = " inForwardingLookupMiss (VOQID 81)",
    [82] = " inNoForwardingAction (VOQID 82)",
    [83] = " inIntfMplsDisabled (VOQID 83)",
    [84] = " inSourcePortFilter (VOQID 84)",
    [85] = " inEtreeLeaf (VOQID 85)",
    [86] = " inEncapBumFilter (VOQID 86)",
    [87] = " inVplsStandbyPw (VOQID 87)",
    [88] = " inPtp (VOQID 88)",
    [89] = " inMcastEmptyMcid (VOQID 89)",
    [90] = " inAcl (VOQID 90)",
    [91] = " inMcastNoCpu (VOQID 91)",
    [92] = " inLagDiscarding (VOQID 92)",
    [93] = " inOam (VOQID 93)",
}

-- Function to get a string representation from an integer value
function get_string_from_integer(value)
    return integer_to_string_map[value] or "Unknown VOQID: " .. tostring(value)
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

  local subtree = tree:add(arista_voq, buf(offset,32), "Arista VoQ Monitor")
  local voq_value = buf(offset+24, 1):uint()
  subtree:add(f_voq, get_string_from_integer(voq_value))
  subtree:add(f_fwd_vsi, buf(offset+15, 2))
end

etypetable:add(arista_ethertype, arista_voq)
