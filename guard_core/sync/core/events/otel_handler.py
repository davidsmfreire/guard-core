from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("guard_core")

try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    _otel_available = True
except ImportError:
    metrics = None
    trace = None
    OTLPMetricExporter = None
    OTLPSpanExporter = None
    MeterProvider = None
    PeriodicExportingMetricReader = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None
    TraceContextTextMapPropagator = None
    _otel_available = False


_EVENT_SPAN_ATTRS: tuple[tuple[str, str], ...] = (
    ("guard.ip_address", "ip_address"),
    ("guard.action_taken", "action_taken"),
    ("guard.reason", "reason"),
    ("guard.endpoint", "endpoint"),
    ("guard.method", "method"),
)


class OtelHandler:
    def __init__(self, config: Any) -> None:
        self._config = config
        self._tracer: Any = None
        self._meter: Any = None
        self._rt_histogram: Any = None
        self._request_counter: Any = None
        self._error_counter: Any = None

    def start(self) -> None:
        if not _otel_available:
            logger.warning("opentelemetry-sdk not installed, OTEL handler disabled")
            return
        attrs: dict[str, Any] = {"service.name": self._config.otel_service_name}
        extra = getattr(self._config, "otel_resource_attributes", {}) or {}
        attrs.update(extra)
        resource = Resource.create(attrs)
        endpoint = self._config.otel_exporter_endpoint
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(tp)
        self._tracer = trace.get_tracer("guard_core.otel")
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint))
        mp = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(mp)
        self._meter = metrics.get_meter("guard_core.otel")
        self._rt_histogram = self._meter.create_histogram(
            "guard.request.duration", unit="s"
        )
        self._request_counter = self._meter.create_counter("guard.request.count")
        self._error_counter = self._meter.create_counter("guard.error.count")

    def stop(self) -> None:
        if self._tracer and _otel_available:
            tracer_provider = trace.get_tracer_provider()
            if hasattr(tracer_provider, "shutdown"):
                tracer_provider.shutdown()
            self._tracer = None
        if self._meter and _otel_available:
            meter_provider = metrics.get_meter_provider()
            if hasattr(meter_provider, "shutdown"):
                meter_provider.shutdown()
            self._meter = None

    def send_event(self, event: Any) -> None:
        if not _otel_available or not self._tracer:
            return
        event_type = getattr(event, "event_type", "unknown")
        metadata = getattr(event, "metadata", {}) or {}
        parent_ctx = self._extract_parent_context(metadata)

        with self._tracer.start_as_current_span(
            f"guard.event.{event_type}", context=parent_ctx
        ) as span:
            self._apply_event_attributes(span, event, event_type)
            self._forward_enrichment_metadata(span, metadata)

    def _extract_parent_context(self, metadata: Any) -> Any:
        if not isinstance(metadata, dict):
            return None
        traceparent = metadata.get("traceparent")
        if not traceparent:
            return None
        carrier: dict[str, str] = {"traceparent": traceparent}
        tracestate = metadata.get("tracestate")
        if tracestate:
            carrier["tracestate"] = tracestate
        try:
            return TraceContextTextMapPropagator().extract(carrier=carrier)
        except Exception:
            return None

    def _apply_event_attributes(self, span: Any, event: Any, event_type: str) -> None:
        span.set_attribute("guard.event_type", event_type)
        for attr_key, event_attr in _EVENT_SPAN_ATTRS:
            span.set_attribute(attr_key, getattr(event, event_attr, ""))
        status_code = getattr(event, "status_code", 0)
        if status_code:
            span.set_attribute("guard.status_code", status_code)

    def _forward_enrichment_metadata(self, span: Any, metadata: Any) -> None:
        if not isinstance(metadata, dict):
            return
        for key, value in metadata.items():
            if (
                key.startswith("guard.")
                and key not in ("traceparent", "tracestate")
                and value is not None
            ):
                span.set_attribute(key, value)

    def send_metric(self, metric: Any) -> None:
        if not _otel_available or not self._meter:
            return
        metric_type = getattr(metric, "metric_type", "unknown")
        value = getattr(metric, "value", 0)
        endpoint = getattr(metric, "endpoint", "")
        tags = getattr(metric, "tags", {}) or {}
        attrs = {"endpoint": endpoint, **tags}
        if metric_type == "response_time" and self._rt_histogram:
            self._rt_histogram.record(value, attributes=attrs)
        elif metric_type == "request_count" and self._request_counter:
            self._request_counter.add(value, attributes=attrs)
        elif metric_type == "error_rate" and self._error_counter:
            self._error_counter.add(value, attributes=attrs)
        else:
            logger.warning(
                "Unknown OTEL metric type %s - no instrument recorded", metric_type
            )

    def initialize_redis(self, redis_handler: Any) -> None:
        pass

    def flush_buffer(self) -> None:
        pass

    def get_dynamic_rules(self) -> Any | None:
        return None

    def health_check(self) -> bool:
        return _otel_available
