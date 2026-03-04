using System;

namespace ZeroTrace.Core.Utilities;

internal static class CommandLineParser
{
    internal sealed record ParsedCommand(string FileName, string Arguments);

    public static ParsedCommand? TryParse(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        commandLine = commandLine.Trim();

        if (commandLine.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = commandLine.IndexOf('"', 1);
            if (endQuote <= 1)
            {
                return null;
            }

            var fileName = commandLine[1..endQuote];
            var args = commandLine[(endQuote + 1)..].Trim();
            return new ParsedCommand(fileName, args);
        }

        var firstSpace = commandLine.IndexOf(' ');
        if (firstSpace < 0)
        {
            return new ParsedCommand(commandLine, string.Empty);
        }

        var exe = commandLine[..firstSpace];
        var arguments = commandLine[(firstSpace + 1)..].Trim();
        return new ParsedCommand(exe, arguments);
    }
}

