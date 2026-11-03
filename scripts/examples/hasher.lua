-- @capability crypto
-- @capability random
-- Hashing service: SHA-256 digests and random tokens.

function handle(req)
    local method = req.method
    if method == "sha256" then
        return { digest = crypto.sha256(req.data or "") }
    elseif method == "token" then
        return { token = crypto.to_hex(random.bytes(16)) }
    elseif method == "equal" then
        return { equal = crypto.ct_eq(req.a or "", req.b or "") }
    else
        error("unknown method: " .. tostring(method))
    end
end
