// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Server.Kestrel.Core;

internal enum ConnectionEndReason
{
    Unknown,
    ConnectionReset,
    FlowControlWindowExceeded,
    KeepAliveTimeout,
    InsufficientTlsVersion,
    InvalidHandshake,
    InvalidStreamId,
    FrameAfterStreamClose,
    UnknownStream,
    UnsupportedFrame,
    UnexpectedFrame,
    InvalidFrameLength,
    InvalidDataPadding,
    InvalidRequestHeaders,
    StreamResetLimitExceeded,
    WindowUpdateSizeInvalid,
    StreamSelfDependency,
    InvalidSettings,
    MissingStreamEnd,
    MaxFrameLengthExceeded,
    ErrorReadingHeaders,
    ErrorWritingHeaders,
    UnexpectedError,
    InvalidHttpVersion,
    RequestHeadersTimeout,
    MinRequestBodyDataRate,
    MinResponseDataRate,
    FlowControlQueueSizeExceeded,
    OutputQueueSizeExceeded,
    ClosedCriticalStream,
    AbortedByApp,
    ServerTimeout,
    StreamCreationError,
    IOError,
    ClientGoAway,
    AppShutdown,
    TransportCompleted,
    TlsHandshakeFailed
}
