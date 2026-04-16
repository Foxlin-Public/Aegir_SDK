package cloud.foxlin.aegir.security;

import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

public final class AegirDiagnosticsHooks
{
    public static final class LogEntry
    {
        private final String level;
        private final String eventName;
        private final String message;
        private final String operation;
        private final String correlationId;
        private final String occurredAtUtc;
        private final Map<String, String> metadata;

        public LogEntry(String level, String eventName, String message, String operation, String correlationId, String occurredAtUtc, Map<String, String> metadata)
        {
            this.level = level;
            this.eventName = eventName;
            this.message = message;
            this.operation = operation;
            this.correlationId = correlationId;
            this.occurredAtUtc = occurredAtUtc;
            this.metadata = metadata;
        }

        public String level() { return level; }
        public String eventName() { return eventName; }
        public String message() { return message; }
        public String operation() { return operation; }
        public String correlationId() { return correlationId; }
        public String occurredAtUtc() { return occurredAtUtc; }
        public Map<String, String> metadata() { return metadata; }
    }

    public static final class MetricEvent
    {
        private final String metricName;
        private final double value;
        private final String unit;
        private final String observedAtUtc;
        private final Map<String, String> dimensions;

        public MetricEvent(String metricName, double value, String unit, String observedAtUtc, Map<String, String> dimensions)
        {
            this.metricName = metricName;
            this.value = value;
            this.unit = unit;
            this.observedAtUtc = observedAtUtc;
            this.dimensions = dimensions;
        }

        public String metricName() { return metricName; }
        public double value() { return value; }
        public String unit() { return unit; }
        public String observedAtUtc() { return observedAtUtc; }
        public Map<String, String> dimensions() { return dimensions; }
    }

    public static final class TraceEvent
    {
        private final String traceName;
        private final String operation;
        private final String tracePhase;
        private final String occurredAtUtc;
        private final String correlationId;
        private final Map<String, String> metadata;

        public TraceEvent(String traceName, String operation, String tracePhase, String occurredAtUtc, String correlationId, Map<String, String> metadata)
        {
            this.traceName = traceName;
            this.operation = operation;
            this.tracePhase = tracePhase;
            this.occurredAtUtc = occurredAtUtc;
            this.correlationId = correlationId;
            this.metadata = metadata;
        }

        public String traceName() { return traceName; }
        public String operation() { return operation; }
        public String tracePhase() { return tracePhase; }
        public String occurredAtUtc() { return occurredAtUtc; }
        public String correlationId() { return correlationId; }
        public Map<String, String> metadata() { return metadata; }
    }

    private final Consumer<LogEntry> logConsumer;
    private final Consumer<MetricEvent> metricConsumer;
    private final Consumer<TraceEvent> traceConsumer;

    public AegirDiagnosticsHooks(
        Consumer<LogEntry> logConsumer,
        Consumer<MetricEvent> metricConsumer,
        Consumer<TraceEvent> traceConsumer)
    {
        this.logConsumer = logConsumer;
        this.metricConsumer = metricConsumer;
        this.traceConsumer = traceConsumer;
    }

    public void emitLog(LogEntry entry)
    {
        if (Objects.nonNull(logConsumer))
        {
            logConsumer.accept(entry);
        }
    }

    public void emitMetric(MetricEvent event)
    {
        if (Objects.nonNull(metricConsumer))
        {
            metricConsumer.accept(event);
        }
    }

    public void emitTrace(TraceEvent event)
    {
        if (Objects.nonNull(traceConsumer))
        {
            traceConsumer.accept(event);
        }
    }
}
