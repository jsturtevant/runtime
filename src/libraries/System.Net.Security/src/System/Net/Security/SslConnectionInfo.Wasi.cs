// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Authentication;

namespace System.Net.Security
{
    internal partial struct SslConnectionInfo
    {
        public void UpdateSslConnectionInfo(SafeDeleteSslContext context)
        {
            // These two are not exposed yet
            // Protocol = (int)MapProtocolVersion(context.ClientConnection.ProtocolVersion());
            // TlsCipherSuite = (TlsCipherSuite)(context.ClientConnection.CipherSuite() ?? throw new Exception());
            if (context.ClientConnection?.AlpnId() is byte[] alpn) {
                ApplicationProtocol =  alpn switch
                {
                    _ when alpn.SequenceEqual(s_http1) => s_http1,
                    _ when alpn.SequenceEqual(s_http2) => s_http2,
                    _ when alpn.SequenceEqual(s_http3) => s_http3,
                    _ when alpn.Length > 0 => alpn.ToArray(),
                    _ when alpn.Length > 0 => alpn.ToArray(),
                    _ => throw new Exception("unknown")
                };
            }
        }

        private static SslProtocols MapProtocolVersion(ushort? version)
        {
            // https://github.com/WebAssembly/wasi-sockets/pull/104
            // TLS protocol version.
            //
            // At the time of writing, these are the existing TLS versions:
            // - 0x0200: SSLv2 (Deprecated)
            // - 0x0300: SSLv3 (Deprecated)
            // - 0x0301: TLSv1.0 (Deprecated)
            // - 0x0302: TLSv1.1 (Deprecated)
            // - 0x0303: TLSv1.2
            // - 0x0304: TLSv1.3
            //

            switch (version)
            {
#pragma warning disable 0618
                case 0x0200:
                    return SslProtocols.Ssl2;
                case 0x0300:
                    return SslProtocols.Ssl3;
#pragma warning restore
#pragma warning disable SYSLIB0039
                case 0x0301:
                    return SslProtocols.Tls;
                case 0x0302:
                    return SslProtocols.Tls11;
#pragma warning restore SYSLIB0039
                case 0x0303:
                    return SslProtocols.Tls12;
                case 0x0304:
                    return SslProtocols.Tls13;
                default:
                    return SslProtocols.None;
            }
        }
    }
}
