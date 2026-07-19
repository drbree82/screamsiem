import pytest
from screamsiem.approvals.tokens import ApprovalToken
from screamsiem.bridges.mcp_server import HostBridge
from screamsiem.ssh.fake_transport import FakeSSHTransport

@pytest.mark.asyncio
async def test_mutation_requires_exact_single_use_approval():
    fake=FakeSSHTransport({"stat":"8421 (python3) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 1234567 21\n","kill":""})
    bridge=HostBridge("h",fake,9100,approval_secret="secret")
    args={"pid":8421,"expected_start_time":"1234567"}
    assert (await bridge.call_mutable("stop_process",args))["status"]=="approval_required"
    token=ApprovalToken.issue("act","h","stop_process",args,"secret")
    assert (await bridge.call_mutable("stop_process",args,token))["status"]=="success"
    assert (await bridge.call_mutable("stop_process",args,token))["error"]=="approval token replayed"
