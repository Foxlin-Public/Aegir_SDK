package cloud.foxlin.aegir.security;

import java.util.List;
import java.util.Map;

public final class SecurityModels
{
    private SecurityModels()
    {
    }

    public static final class IdentityGraphSnapshot
    {
        private final Map<String, Object> payload;

        IdentityGraphSnapshot(Map<String, Object> payload)
        {
            this.payload = payload;
        }

        public String getGraphId()
        {
            return (String) payload.get("graphId");
        }

        public Map<String, Object> getPayload()
        {
            return payload;
        }
    }

    public static final class ExposureSummary
    {
        private final Map<String, Object> payload;

        ExposureSummary(Map<String, Object> payload)
        {
            this.payload = payload;
        }

        public String getSummaryText()
        {
            return (String) payload.get("summaryText");
        }

        public Map<String, Object> getPayload()
        {
            return payload;
        }
    }

    public static final class IdentityActionRecord
    {
        private final Map<String, Object> payload;

        IdentityActionRecord(Map<String, Object> payload)
        {
            this.payload = payload;
        }

        public String getActionType()
        {
            return (String) payload.get("actionType");
        }

        public String getStatus()
        {
            return (String) payload.get("status");
        }

        public String getActionId()
        {
            return (String) payload.get("actionId");
        }

        public Map<String, Object> getPayload()
        {
            return payload;
        }
    }

    public static final class ScanIdentityResult
    {
        private final Map<String, Object> payload;
        private final IdentityGraphSnapshot graph;
        private final ExposureSummary exposure;
        private final List<IdentityActionRecord> actionHistory;

        ScanIdentityResult(Map<String, Object> payload, IdentityGraphSnapshot graph, ExposureSummary exposure, List<IdentityActionRecord> actionHistory)
        {
            this.payload = payload;
            this.graph = graph;
            this.exposure = exposure;
            this.actionHistory = actionHistory;
        }

        public String getSubjectId()
        {
            return (String) payload.get("subjectId");
        }

        public IdentityGraphSnapshot getGraph()
        {
            return graph;
        }

        public ExposureSummary getExposure()
        {
            return exposure;
        }

        public List<IdentityActionRecord> getActionHistory()
        {
            return actionHistory;
        }
    }
}
