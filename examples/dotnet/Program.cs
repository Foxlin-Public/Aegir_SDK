using Foxlin.Aegir.Auth.Models;
using Foxlin.Aegir.Auth.Services;

DateTimeOffset now = new(2026, 4, 7, 15, 0, 0, TimeSpan.Zero);
IdentityGraphSnapshot graph = new(
    "graph:developer:dev_123",
    now,
    [
        new IdentityGraphNode(
            "developer:dev_123",
            IdentityGraphNodeType.User,
            "dev_123@example.com",
            "active",
            "high",
            new Dictionary<string, string?>(),
            now,
            now)
    ],
    Array.Empty<IdentityGraphEdge>(),
    new IdentityGraphScores(0.15m, 0.92m, 0.88m),
    new Dictionary<string, string?>());

ExposureSummary exposure = new(
    graph.GraphId,
    now,
    0.15m,
    Array.Empty<ExposureFinding>(),
    "Low exposure posture.");

IdentityActionRecord completedAction = new(
    "action_001",
    "developer:dev_123",
    IdentityActionType.VerifyConnection,
    IdentityActionStatus.Completed,
    "application:app_portal",
    "NuGet sample validation.",
    now,
    null,
    null,
    new Dictionary<string, string?>());

IAegirSecurityProvider provider = new AegirSecurityProvider(
    new SampleIdentitySecurityService(graph, exposure, completedAction),
    new IdentityGraphSerializer());

ScanIdentityResult scan = await provider.ScanIdentityAsync("developer:dev_123");
string graphJson = await provider.GetIdentityGraphJsonAsync("developer:dev_123");
ExposureSummary exposureSummary = await provider.GetExposureSummaryAsync("developer:dev_123");
IdentityActionRecord action = await provider.PerformActionAsync(
    new PerformIdentityActionRequest(
        "developer:dev_123",
        IdentityActionType.VerifyConnection,
        "application:app_portal",
        "NuGet sample validation."));

bool containsGraphId = graphJson.Contains("graph:developer:dev_123", StringComparison.Ordinal);

Console.WriteLine("NuGet sample executed successfully.");
Console.WriteLine($"Provider surface available: {nameof(IAegirSecurityProvider)}");
Console.WriteLine($"Scan subject: {scan.SubjectId}");
Console.WriteLine($"Graph ID: {scan.Graph.GraphId}");
Console.WriteLine($"Exposure summary: {exposureSummary.SummaryText}");
Console.WriteLine($"Action result: {action.ActionType} -> {action.Status}");
Console.WriteLine($"Serialized graph contains graphId: {containsGraphId}");

internal sealed class SampleIdentitySecurityService : IIdentitySecurityService
{
    private readonly IdentityGraphSnapshot _graph;
    private readonly ExposureSummary _exposure;
    private readonly IdentityActionRecord _action;

    public SampleIdentitySecurityService(
        IdentityGraphSnapshot graph,
        ExposureSummary exposure,
        IdentityActionRecord action)
    {
        _graph = graph;
        _exposure = exposure;
        _action = action;
    }

    public ValueTask<ScanIdentityResult> ScanIdentityAsync(string subjectId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new ScanIdentityResult(subjectId, _graph, _exposure, [_action]));

    public ValueTask<IdentityGraphSnapshot> GetIdentityGraphAsync(string subjectId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_graph);

    public ValueTask<ExposureSummary> GetExposureSummaryAsync(string subjectId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_exposure);

    public ValueTask<IdentityActionRecord> PerformActionAsync(PerformIdentityActionRequest request, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_action);

    public ValueTask<IdentityActionRecord> ReverseActionAsync(string actionId, string? reason = null, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_action with
        {
            ActionId = actionId,
            Status = IdentityActionStatus.Reversed,
            ReverseReason = reason,
            ReversedAtUtc = _action.RequestedAtUtc.AddMinutes(1)
        });

    public ValueTask<IReadOnlyList<IdentityActionRecord>> GetActionHistoryAsync(string subjectId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<IReadOnlyList<IdentityActionRecord>>([_action]);
}
