"""OpenTelemetry GenAI + OpenInference semantic-convention instrumentation for hveritas."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from openinference.semconv.trace import OpenInferenceSpanKindValues, SpanAttributes
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as ga
from opentelemetry.trace import Span, Status, StatusCode

from hveritas.ledger.canonical import DeterministicClock, SeededIdGenerator, canonical_json
from hveritas.ledger.models import SpanRecord

if TYPE_CHECKING:
    from hveritas.ledger.store import AppendOnlyLedger

# Canonical GenAI operation names
OP_INVOKE_AGENT = ga.GenAiOperationNameValues.INVOKE_AGENT.value  # "invoke_agent"
OP_EXECUTE_TOOL = ga.GenAiOperationNameValues.EXECUTE_TOOL.value  # "execute_tool"
OP_PLAN = "plan"  # GenAI planning operation span per hveritas M0 contract
OP_CHAT = ga.GenAiOperationNameValues.CHAT.value  # "chat"
OP_EVALUATE = "evaluate"

VALID_GENAI_OPERATIONS = frozenset(
    {OP_INVOKE_AGENT, OP_EXECUTE_TOOL, OP_PLAN, OP_CHAT, OP_EVALUATE}
)

ATTR_STEP_INDEX = "hveritas.step.index"
ATTR_RUN_ID = "hveritas.run.id"
ATTR_PLAN_TARGET = "hveritas.plan.target"


def format_semconv_span_name(operation: str, target_name: str | None = None) -> str:
    """Format span name strictly per OTel GenAI Semantic Conventions.

    Per OTel GenAI SemConv (`gen-ai-agent-spans` / `gen-ai-spans`):
    - `invoke_agent {gen_ai.agent.name}` or `invoke_agent`
    - `execute_tool {gen_ai.tool.name}` or `execute_tool`
    - `plan {target}` or `plan`
    """
    if operation not in VALID_GENAI_OPERATIONS:
        raise ValueError(f"Unsupported GenAI operation name: {operation!r}")
    if target_name:
        return f"{operation} {target_name}"
    return operation


def validate_semconv_span(span: SpanRecord) -> list[str]:
    """Validate that a SpanRecord conforms to OTel GenAI + OpenInference SemConv.

    Returns an empty list if valid, or a list of human-readable violation messages.
    """
    errors: list[str] = []
    op = span.attributes.get(ga.GEN_AI_OPERATION_NAME)
    if op not in VALID_GENAI_OPERATIONS:
        errors.append(
            f"Missing or invalid {ga.GEN_AI_OPERATION_NAME}: {op!r} "
            f"(expected one of {sorted(VALID_GENAI_OPERATIONS)})"
        )
        return errors

    if span.operation_name != op:
        errors.append(f"span.operation_name={span.operation_name!r} != attr {op!r}")

    if not (span.name == op or span.name.startswith(f"{op} ")):
        errors.append(
            f"Span name {span.name!r} violates OTel GenAI naming rule '{op}' or '{op} <target>'"
        )

    oi_kind = span.attributes.get(SpanAttributes.OPENINFERENCE_SPAN_KIND)
    if not oi_kind:
        errors.append(f"Missing {SpanAttributes.OPENINFERENCE_SPAN_KIND}")

    if op == OP_INVOKE_AGENT:
        if oi_kind != OpenInferenceSpanKindValues.AGENT.value:
            errors.append(f"invoke_agent must have AGENT kind, got {oi_kind!r}")
        if " " in span.name and not span.attributes.get(ga.GEN_AI_AGENT_NAME):
            errors.append(f"Suffixed invoke_agent span missing {ga.GEN_AI_AGENT_NAME}")
    elif op == OP_EXECUTE_TOOL:
        if oi_kind != OpenInferenceSpanKindValues.TOOL.value:
            errors.append(f"execute_tool must have TOOL kind, got {oi_kind!r}")
        if not span.attributes.get(ga.GEN_AI_TOOL_NAME):
            errors.append(f"execute_tool missing {ga.GEN_AI_TOOL_NAME}")
        if not span.attributes.get(ga.GEN_AI_TOOL_CALL_ID):
            errors.append(f"execute_tool missing {ga.GEN_AI_TOOL_CALL_ID}")
    elif op == OP_PLAN:
        if oi_kind not in {
            OpenInferenceSpanKindValues.CHAIN.value,
            OpenInferenceSpanKindValues.AGENT.value,
        }:
            errors.append(f"plan must have CHAIN/AGENT kind, got {oi_kind!r}")

    if span.end_time_ns < span.start_time_ns:
        errors.append("end_time_ns < start_time_ns")

    return errors


class LedgerSpanProcessor(SpanProcessor):
    """OTel SpanProcessor that persists every ended GenAI span into AppendOnlyLedger."""

    def __init__(self, ledger: AppendOnlyLedger, run_id: str) -> None:
        self._ledger = ledger
        self._run_id = run_id
        self._seq = 0

    def on_start(self, span: Span, parent_context: otel_context.Context | None = None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        attrs = dict(span.attributes or {})
        run_id = str(attrs.get(ATTR_RUN_ID, self._run_id))
        if run_id != self._run_id:
            return
        op_name = str(attrs.get(ga.GEN_AI_OPERATION_NAME, span.name.split(" ", 1)[0]))
        oi_kind = str(
            attrs.get(
                SpanAttributes.OPENINFERENCE_SPAN_KIND,
                OpenInferenceSpanKindValues.UNKNOWN.value,
            )
        )
        step_idx_raw = attrs.get(ATTR_STEP_INDEX)
        step_index = int(step_idx_raw) if isinstance(step_idx_raw, int) else None

        ctx = span.get_span_context()
        if ctx is None:
            return
        trace_id_hex = f"{ctx.trace_id:032x}"
        span_id_hex = f"{ctx.span_id:016x}"
        parent_hex = f"{span.parent.span_id:016x}" if span.parent is not None else None

        record = SpanRecord(
            run_id=self._run_id,
            seq_no=self._seq,
            trace_id=trace_id_hex,
            span_id=span_id_hex,
            parent_span_id=parent_hex,
            step_index=step_index,
            name=span.name,
            operation_name=op_name,
            openinference_kind=oi_kind,
            start_time_ns=int(span.start_time or 0),
            end_time_ns=int(span.end_time or 0),
            status_code=span.status.status_code.name,
            attributes={k: _normalize_attr(v) for k, v in sorted(attrs.items())},
        )
        self._seq += 1
        self._ledger.append_span(record)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def _normalize_attr(val: Any) -> Any:
    if isinstance(val, (str, int, float, bool)) or val is None:
        return val
    if isinstance(val, (list, tuple)):
        return [_normalize_attr(x) for x in val]
    return str(val)


class HVeritasTracer:
    """Isolated per-run OTel Tracer emitting GenAI + OpenInference semantic spans."""

    def __init__(
        self,
        ledger: AppendOnlyLedger,
        run_id: str,
        seed: int = 42,
        clock: DeterministicClock | None = None,
    ) -> None:
        self.ledger = ledger
        self.run_id = run_id
        self.seed = seed
        self.clock = clock or DeterministicClock()
        resource = Resource.create(
            {
                "service.name": "hveritas",
                "service.version": "0.1.0",
                ATTR_RUN_ID: run_id,
            }
        )
        self._provider = TracerProvider(
            resource=resource,
            id_generator=SeededIdGenerator(seed),
        )
        self._processor = LedgerSpanProcessor(ledger=ledger, run_id=run_id)
        self._provider.add_span_processor(self._processor)
        self._tracer = self._provider.get_tracer("hveritas.genai", "0.1.0")

    @contextmanager
    def invoke_agent(
        self,
        agent_name: str | None = None,
        agent_id: str = "worker-0",
        model: str = "deterministic-worker",
        exact_span_name: bool = False,
    ) -> Iterator[Span]:
        span_name = (
            OP_INVOKE_AGENT
            if exact_span_name
            else format_semconv_span_name(OP_INVOKE_AGENT, agent_name)
        )
        attrs: dict[str, Any] = {
            ATTR_RUN_ID: self.run_id,
            ga.GEN_AI_OPERATION_NAME: OP_INVOKE_AGENT,
            ga.GEN_AI_AGENT_ID: agent_id,
            ga.GEN_AI_REQUEST_MODEL: model,
            ga.GEN_AI_REQUEST_SEED: self.seed,
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.AGENT.value,
        }
        if agent_name:
            attrs[ga.GEN_AI_AGENT_NAME] = agent_name
        with self._managed_span(span_name, attrs) as span:
            yield span

    @contextmanager
    def plan(
        self,
        plan_target: str | None = None,
        step_index: int | None = None,
        exact_span_name: bool = False,
    ) -> Iterator[Span]:
        span_name = OP_PLAN if exact_span_name else format_semconv_span_name(OP_PLAN, plan_target)
        attrs: dict[str, Any] = {
            ATTR_RUN_ID: self.run_id,
            ga.GEN_AI_OPERATION_NAME: OP_PLAN,
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
        }
        if plan_target:
            attrs[ATTR_PLAN_TARGET] = plan_target
        if step_index is not None:
            attrs[ATTR_STEP_INDEX] = step_index
        with self._managed_span(span_name, attrs) as span:
            yield span

    @contextmanager
    def execute_tool(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        step_index: int,
        call_id: str | None = None,
        tool_type: str = "function",
        exact_span_name: bool = False,
    ) -> Iterator[Span]:
        span_name = (
            OP_EXECUTE_TOOL
            if exact_span_name
            else format_semconv_span_name(OP_EXECUTE_TOOL, tool_name)
        )
        resolved_call_id = call_id or f"{self.run_id}-call-{step_index:04d}"
        attrs: dict[str, Any] = {
            ATTR_RUN_ID: self.run_id,
            ATTR_STEP_INDEX: step_index,
            ga.GEN_AI_OPERATION_NAME: OP_EXECUTE_TOOL,
            ga.GEN_AI_TOOL_NAME: tool_name,
            ga.GEN_AI_TOOL_CALL_ID: resolved_call_id,
            ga.GEN_AI_TOOL_TYPE: tool_type,
            ga.GEN_AI_TOOL_CALL_ARGUMENTS: canonical_json(tool_args),
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.TOOL.value,
        }
        with self._managed_span(span_name, attrs) as span:
            yield span

    @contextmanager
    def _managed_span(self, name: str, attributes: dict[str, Any]) -> Iterator[Span]:
        start_ns = self.clock.now_ns()
        span = self._tracer.start_span(
            name=name,
            attributes=attributes,
            start_time=start_ns,
        )
        token = otel_context.attach(trace.set_span_in_context(span))
        try:
            yield span
            if span.is_recording():
                span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            if span.is_recording():
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
        finally:
            otel_context.detach(token)
            end_ns = self.clock.now_ns()
            span.end(end_time=end_ns)

    def shutdown(self) -> None:
        self._provider.force_flush()
        self._provider.shutdown()


def export_opik_trace_bundle(spans: list[SpanRecord]) -> list[dict[str, Any]]:
    """Convert SpanRecords to Opik-compatible trace/span dictionaries (Apache-2.0 trace sink)."""
    out: list[dict[str, Any]] = []
    for s in spans:
        out.append(
            {
                "id": s.span_id,
                "trace_id": s.trace_id,
                "parent_span_id": s.parent_span_id,
                "name": s.name,
                "type": "tool"
                if s.operation_name == OP_EXECUTE_TOOL
                else ("llm" if s.operation_name == OP_CHAT else "general"),
                "start_time_ns": s.start_time_ns,
                "end_time_ns": s.end_time_ns,
                "metadata": s.attributes,
            }
        )
    return out
