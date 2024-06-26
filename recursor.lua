DESEC_DOMAIN = (os.getenv("DESEC_DOMAIN") or "")
localPoC1 = newDN("pdns.")
globalPoC1 = newDN("pdns."..DESEC_DOMAIN)
localPoC2 = newDN("bind9.")
globalPoC2 = newDN("bind9."..DESEC_DOMAIN)

if DESEC_DOMAIN ~= "" then
  pdnslog("Accepting queries for **."..localPoC1:toString().." and **."..globalPoC1:toString()..".")
  pdnslog("Accepting queries for **."..localPoC2:toString().." and **."..globalPoC2:toString()..".")
else
  pdnslog("Accepting queries for **."..localPoC1:toString()..".")
  pdnslog("Accepting queries for **."..localPoC2:toString()..".")
end

function preresolve(dq)
  isLocalPoC = dq.qname:isPartOf(localPoC1) or dq.qname:isPartOf(localPoC2)
  isGlobalPoC = DESEC_DOMAIN ~= "" and (dq.qname:isPartOf(globalPoC1) or dq.qname:isPartOf(globalPoC2))
  isPoC = isLocalPoC or isGlobalPoC
  if not isPoC then
    dq.rcode = 5  -- REFUSED
    return true
  end
  return false
end
