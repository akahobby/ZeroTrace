using System;

namespace ZeroTrace.Core.Services;

public interface ILogService
{
    event EventHandler<string>? MessageLogged;

    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

