using System;
using System.Reflection;
using System.Text;
using System.Windows;

namespace SurgeApp.Services;

/// <summary>
/// Single place where an exception becomes something a user sees.
///
/// <para>Release builds show only the exception <c>Message</c>. Stack traces were previously
/// concatenated straight into <c>MessageBox.Show</c>, which leaked internal namespaces, class and
/// method names, file paths and build layout to anyone who could trigger an error — a free map of
/// the licensing and anti-tamper code for someone attempting to crack it, and noise for everyone
/// else. Full detail still goes to the tamper-evident local log, which is where support should
/// read it from.</para>
/// </summary>
public static class ErrorReporter
{
    /// <summary>Product version, read from the assembly instead of a hardcoded string.</summary>
    public static Version CurrentVersion =>
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0, 0);

    /// <summary>Three-component display form, e.g. "19.4.1".</summary>
    public static string CurrentVersionDisplay => CurrentVersion.ToString(3);

    /// <summary>Text safe to put in front of a user for the current build configuration.</summary>
    public static string UserFacingDetail(Exception ex)
    {
#if DEBUG
        return ex.ToString();
#else
        var sb = new StringBuilder();
        sb.Append(ex.Message);

        // Inner messages are useful (e.g. "The remote name could not be resolved") and carry no
        // layout information, so they stay. Stack traces do not.
        var inner = ex.InnerException;
        var depth = 0;
        while (inner is not null && depth++ < 3)
        {
            sb.AppendLine().Append("→ ").Append(inner.Message);
            inner = inner.InnerException;
        }
        return sb.ToString();
#endif
    }

    /// <summary>Logs the full exception locally, then shows the sanitised message.</summary>
    public static void Show(string title, string heading, Exception ex, MessageBoxImage icon = MessageBoxImage.Error)
    {
        Log(title, ex);
        var body = new StringBuilder()
            .AppendLine(heading)
            .AppendLine()
            .AppendLine(UserFacingDetail(ex))
            .AppendLine()
            .Append("A diagnostic log was written to:")
            .AppendLine()
            .Append(SecureLogManager.LogFile)
            .ToString();

        try { MessageBox.Show(body, title, MessageBoxButton.OK, icon); } catch { /* no UI available */ }
    }

    /// <summary>Writes the full exception (stack trace included) to the local protected log only.</summary>
    public static void Log(string context, Exception ex)
    {
        try
        {
            SecureLogManager.Write(new
            {
                type = "error",
                context,
                timeUtc = DateTime.UtcNow,
                version = CurrentVersionDisplay,
                user = Environment.UserName,
                error = ex.ToString()
            });
        }
        catch
        {
            // Diagnostics must never be the reason an operation fails.
        }
    }
}
