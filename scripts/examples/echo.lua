-- @capability log
-- Echoes the request back. Simplest possible service script.

function handle(req)
    log("info", "echoing request")
    return { echo = req }
end
