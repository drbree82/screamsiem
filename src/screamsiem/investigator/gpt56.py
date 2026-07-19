from __future__ import annotations

import asyncio
import json
from typing import Any

from ..models import Event, Finding, Investigation
from .prompts import SYSTEM_PROMPT


class GPTInvestigator:
    def __init__(self, client=None, model="gpt-5.6", timeout=60, max_tool_calls=8): self.client,self.model,self.timeout,self.max_tool_calls=client,model,timeout,max_tool_calls

    async def investigate(self, finding: Finding, host_profile: dict, events: list[Event], tool_adapter=None, previous: dict|None=None) -> Investigation:
        evidence={"finding":finding.model_dump(mode="json"),"host_profile":host_profile,"events":[e.model_dump(mode="json") for e in events[-50:]],"previous":previous,"mutable_capabilities":["stop_process","stop_service","restart_service"]}
        if not self.client:
            return self.fallback(finding,events)
        tools=tool_adapter.schemas() if tool_adapter else []
        try:
            response=await asyncio.wait_for(self._run(evidence,tools,tool_adapter),self.timeout)
            return self._parse(response)
        except Exception:
            return self.fallback(finding,events)

    async def _run(self,evidence,tools,adapter):
        response=await self.client.responses.create(model=self.model,instructions=SYSTEM_PROMPT,input=json.dumps(evidence),tools=tools,reasoning={"effort":"medium"},text={"format":{"type":"json_object"}})
        calls=0
        while getattr(response,"output",None) and calls<self.max_tool_calls:
            function_calls=[x for x in response.output if getattr(x,"type","")=="function_call"]
            if not function_calls: break
            outputs=[]
            for call in function_calls:
                result=await adapter.call(call.name,json.loads(call.arguments)); outputs.append({"type":"function_call_output","call_id":call.call_id,"output":json.dumps(result)[:50000]}); calls+=1
            response=await self.client.responses.create(model=self.model,instructions=SYSTEM_PROMPT,previous_response_id=response.id,input=outputs,tools=tools,text={"format":{"type":"json_object"}})
        return getattr(response,"output_text","")

    def _parse(self,value: Any)->Investigation:
        if isinstance(value,dict): return Investigation.model_validate(value)
        return Investigation.model_validate_json(value)

    @staticmethod
    def fallback(finding: Finding, events: list[Event])->Investigation:
        observations=[{"text":e.summary,"evidence_ids":[e.id]} for e in events[-5:]]
        actions=[]
        for e in events:
            if e.data.get("pid") and e.data.get("start_time"):
                actions.append({"kind":"mcp_action","label":"Stop suspicious process","tool":"stop_process","arguments":{"pid":e.data["pid"],"expected_start_time":str(e.data["start_time"])},"impact":"Terminates the observed process after approval.","risk":"medium"}); break
        actions.append({"kind":"manual_command","label":"Review the host manually","command":"ssh admin@host 'ps auxf && ss -lntup'","impact":"Read-only evidence review.","risk":"low","verification_command":"ssh admin@host 'hostname && uptime'"})
        return Investigation(title=finding.title,severity="critical" if finding.severity=="critical" else finding.severity,confidence=finding.confidence,plain_english_summary=finding.machine_summary,observations=observations,assessment="The deterministic evidence is suspicious and needs operator review. AI analysis is unavailable or running in deterministic demo mode.",alternative_explanations=["An administrator may have made a temporary change."],recommended_actions=actions,next_evidence_to_collect=[])
