from __future__ import annotations


class MCPReadOnlyAdapter:
    """Translates the small bridge tool registry into Responses function tools."""
    def __init__(self, bridge): self.bridge=bridge
    def schemas(self)->list[dict]:
        return [{"type":"function","name":name,"description":description,"parameters":parameters} for name,description,parameters in self.bridge.read_tool_schemas()]
    async def call(self,name:str,arguments:dict):
        if name not in self.bridge.read_tools(): raise ValueError("tool is not read-only or unavailable")
        return await self.bridge.call_read_tool(name,arguments)
