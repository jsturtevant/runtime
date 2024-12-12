// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Security
{
    public partial class SslStream
    {

        private bool _remoteCertificateExposed;
        private readonly SslAuthenticationOptions _sslAuthenticationOptions = new SslAuthenticationOptions();
        private SafeDeleteSslContext? _securityContext;

        private async ValueTask<int> ReadAsyncInternal<TIOAdapter>(Memory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            return await _securityContext!.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        private async ValueTask WriteSingleChunk<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            await _securityContext!.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        // reAuthenticationData is only used on Windows in case of renegotiation.
        private async Task ForceAuthenticationAsync<TIOAdapter>(bool receiveFirst, byte[]? reAuthenticationData, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            if (reAuthenticationData == null)
            {
                // prevent nesting only when authentication functions are called explicitly. e.g. handle renegotiation transparently.
                if (Interlocked.Exchange(ref _nestedAuth, NestedState.StreamInUse) == NestedState.StreamInUse)
                {
                    throw new InvalidOperationException(SR.Format(SR.net_io_invalidnestedcall, "authenticate"));
                }
            }

            if (IsServer)
            {
                // Server authentication is not currently implemented
                throw new NotSupportedException("Server Authentication is not implemented");
            }
            _securityContext = new SafeDeleteSslContext(_sslAuthenticationOptions, InnerStream);

            try
            {
                await _securityContext.AuthenticateAsync().ConfigureAwait(false);
                CompleteHandshake(_sslAuthenticationOptions);
            }
            finally
            {
                if (reAuthenticationData == null)
                {
                    _nestedAuth = NestedState.StreamNotInUse;
                }
            }

#pragma warning disable SYSLIB0058 // Use NegotiatedCipherSuite.
            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Log.SspiSelectedCipherSuite(nameof(ForceAuthenticationAsync),
                                                                    SslProtocol,
                                                                    CipherAlgorithm,
                                                                    CipherStrength,
                                                                    HashAlgorithm,
                                                                    HashStrength,
                                                                    KeyExchangeAlgorithm,
                                                                    KeyExchangeStrength);
#pragma warning restore SYSLIB0058 // Use NegotiatedCipherSuite.
        }
        private static Task RenegotiateAsync<AsyncReadWriteAdapter>(CancellationToken cancellationToken) => throw new PlatformNotSupportedException();

        internal static X509Certificate2? FindCertificateWithPrivateKey(object instance, bool isServer, X509Certificate certificate)
        {
            // We might be able to do this?
            throw new PlatformNotSupportedException();
        }

        private static ProtocolToken GenerateToken(ReadOnlySpan<byte> _, out int consumed)
        {
            // wasi doesn't use tokens just fill in default
            consumed = 0;
            ProtocolToken token = default;
            token.RentBuffer = false;
            token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.OK); ;
            return token;
        }

        internal static X509Certificate? LocalClientCertificate
        {
            get
            {
                return null;
            }
        }

        internal void CloseContext()
        {
            if (!_remoteCertificateExposed)
            {
                _remoteCertificate?.Dispose();
                _remoteCertificate = null;
            }

            _securityContext?.Dispose();
        }
        private static ProtocolToken GenerateAlertToken()
        {
            return GenerateToken(default, out _);
        }

        ~SslStream()
        {
            Dispose(disposing: false);
        }

    }
}
