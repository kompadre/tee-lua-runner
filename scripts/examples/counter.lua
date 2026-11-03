-- @capability state
-- @capability clock
-- @capability log
-- Rolling counter service: demonstrates state + clock capabilities.

function handle(req)
    local method = req.method
    local key = req.key or "default"
    if method == "incr" then
        local v = (state.get(key) or 0) + 1
        state.set(key, v)
        log("info", "incremented " .. key)
        return { key = key, value = v, at = clock.unix_seconds() }
    elseif method == "get" then
        return { key = key, value = state.get(key) or 0 }
    elseif method == "reset" then
        state.delete(key)
        log("info", "reset " .. key)
        return { ok = true }
    else
        error("unknown method: " .. tostring(method))
    end
end
