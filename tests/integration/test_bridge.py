import pytest
from screamsiem.bridges.mcp_server import HostBridge
from screamsiem.ssh.fake_transport import FakeSSHTransport

@pytest.mark.asyncio
async def test_bridge_loopback_and_read_tool_routing():
    fake=FakeSSHTransport({"ps":"1 0 root 1 init /sbin/init\n","hostname":"demo\n"})
    bridge=HostBridge("h",fake,9100)
    bridge.ensure_loopback()
    with pytest.raises(ValueError): bridge.ensure_loopback("0.0.0.0")
    await bridge.start()
    result=await bridge.call_read_tool("list_processes",{})
    assert result[0]["pid"]==1
