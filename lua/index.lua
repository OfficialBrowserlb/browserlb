BrowserLB = {}
BrowserLB.plugins = {}         
BrowserLB._hookIndex = {}       


function BrowserLB.registerPlugin(plugin)
    assert(type(plugin) == "table", "plugin must be a table")
    assert(type(plugin.name) == "string", "plugin.name is required")

    table.insert(BrowserLB.plugins, plugin)

    for _, hookName in ipairs({ "onLoad", "onBeforeNavigate", "onPageLoad", "onSearch" }) do
        if type(plugin[hookName]) == "function" then
            BrowserLB._hookIndex[hookName] = BrowserLB._hookIndex[hookName] or {}
            table.insert(BrowserLB._hookIndex[hookName], plugin.name)
        end
    end

    if plugin.onLoad then
        plugin.onLoad()
    end
    return true
end

function BrowserLB.triggerHook(hookName, value)
    for _, plugin in ipairs(BrowserLB.plugins) do
        local handler = plugin[hookName]
        if handler then
            local result = handler(value)
            if result == false then
                return false, plugin.name  
            elseif result ~= nil then
                value = result              
            end
        end
    end
    return value
end


local AdBlockPlugin = {
    name = "adblock-lite",
    blocklist = {              
        ["ads.example.com"] = true,
        ["tracker.example.net"] = true,
    },
}

function AdBlockPlugin.onLoad()
    print("[adblock-lite] loaded, watching " .. AdBlockPlugin._count() .. " hosts")
end

function AdBlockPlugin._count()
    local n = 0
    for _ in pairs(AdBlockPlugin.blocklist) do n = n + 1 end
    return n
end

function AdBlockPlugin.onBeforeNavigate(url)
    local host = url:match("^https?://([^/]+)")
    if host and AdBlockPlugin.blocklist[host] then
        print("[adblock-lite] blocked navigation to " .. host)
        return false
    end
    if url:match("^http://") then
      
        return (url:gsub("^http://", "https://"))
    end
    return url
end

BrowserLB.registerPlugin(AdBlockPlugin)


local TrafficRules = {}


function TrafficRules.parseRule(ruleString)
    local parts = {}
    for token in ruleString:gmatch("%S+") do
        table.insert(parts, token)
    end

    local rule = { action = parts[1], conditions = {} }
    for i = 2, #parts do
        local key, value = parts[i]:match("([%w_]+)=([^%s]+)")
        if key == "reason" then
            rule.reason = value
        elseif key then
            rule.conditions[key] = value
        end
    end
    return rule
end

function TrafficRules.apply(rule, request)
    for key, expected in pairs(rule.conditions) do
        if request[key] ~= expected then
            return nil 
        end
    end
    return rule.action, rule.reason
end

local PacketParser = {}

function PacketParser.parseHeader(bytes)
    assert(#bytes >= 4, "header requires at least 4 bytes")
    return {
        version = bytes[1],
        flags   = bytes[2],
        length  = (bytes[3] << 8) | bytes[4], 
    }
end


print("== BrowserLB Lua demo ==")

local blockedOrUrl, blocker = BrowserLB.triggerHook("onBeforeNavigate", "http://tracker.example.net/pixel.gif")
print("navigate(tracker) ->", blockedOrUrl, blocker)

local upgraded = BrowserLB.triggerHook("onBeforeNavigate", "http://example.com/")
print("navigate(example.com) ->", upgraded)

local rule = TrafficRules.parseRule("block host=ads.example.com reason=ads")
local action, reason = TrafficRules.apply(rule, { host = "ads.example.com" })
print("traffic rule ->", action, reason)

local header = PacketParser.parseHeader({ 1, 0, 0x01, 0x2C }) 
print(string.format("packet header -> version=%d flags=%d length=%d",
    header.version, header.flags, header.length))
