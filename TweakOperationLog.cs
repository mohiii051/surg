using System;
using System.Collections.Generic;

namespace SurgeApp;

public sealed record TweakLogEntry(
    DateTime TimestampUtc,
    int TweakNumber,
    string TweakTitle,
    string Action,
    string Outcome,
    string VerificationState,
    string Message,
    IReadOnlyList<string> Commands,
    string? Exception = null);

public static class TweakOperationLog
{
    public static string LogDirectory => SecureLogManager.LogFile is null ? "" : System.IO.Path.GetDirectoryName(SecureLogManager.LogFile)!;
    public static string LogFile => SecureLogManager.LogFile;

    public static void Write(TweakLogEntry entry) => SecureLogManager.Write(entry);

    public static string ExportReport(string destinationCsv) => SecureLogManager.ExportCsv(destinationCsv);
}
