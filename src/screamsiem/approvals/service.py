from __future__ import annotations

from datetime import datetime, timezone

from ..database import Database, new_id
from ..models import Action, TimelineEntry
from .tokens import ApprovalToken


class ApprovalService:
    def __init__(self, db: Database, secret: str, bridge_call): self.db,self.secret,self.bridge_call=db,secret,bridge_call

    async def approve(self, action_id: str) -> Action:
        action=await self.db.get_action(action_id)
        if not action: raise KeyError("action not found")
        if action.state!="pending": raise ValueError(f"action is {action.state}")
        now=datetime.now(timezone.utc); token=ApprovalToken.issue(action.id,action.host_id,action.tool or "",action.arguments,self.secret)
        await self.db.update_action(action.id,state="approved",approved_at=now)
        await self.db.add_timeline(TimelineEntry(id=new_id("tl"),finding_id=action.finding_id,created_at=now,entry_type="action_approved",actor="operator",data={"action_id":action.id,"tool":action.tool,"arguments":action.arguments}))
        result=await self.bridge_call(action,token)
        end=datetime.now(timezone.utc); state="executed" if result.get("status")=="success" else "failed"
        await self.db.update_action(action.id,state=state,executed_at=end,result=result)
        await self.db.add_timeline(TimelineEntry(id=new_id("tl"),finding_id=action.finding_id,created_at=end,entry_type="action_result",actor="bridge",data=result))
        action.state,state; action.state=state; action.approved_at=now; action.executed_at=end; action.result=result; return action

    async def reject(self, action_id: str) -> Action:
        action=await self.db.get_action(action_id)
        if not action: raise KeyError("action not found")
        if action.state!="pending": raise ValueError(f"action is {action.state}")
        now=datetime.now(timezone.utc); await self.db.update_action(action.id,state="rejected")
        await self.db.add_timeline(TimelineEntry(id=new_id("tl"),finding_id=action.finding_id,created_at=now,entry_type="action_rejected",actor="operator",data={"action_id":action.id}))
        action.state="rejected"; return action
