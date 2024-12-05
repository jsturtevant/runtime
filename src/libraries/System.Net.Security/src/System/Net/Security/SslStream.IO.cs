// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
namespace System.Net.Security
{
    public partial class SslStream
    {
        private NestedState _nestedAuth;
         // Used by Telemetry to ensure we log connection close exactly once
        private enum ConnectionStatus
        {
            NoHandshake = 0,
            HandshakeCompleted = 1, // connection opened`
            Disposed = 2, // connection closed
        }

        private ConnectionStatus _connectionOpenedStatus;

        private void ReturnReadBufferIfEmpty()
        {
            if (_buffer.ActiveLength == 0)
            {
                _buffer.ReturnBuffer();
            }
        }

        //
        // This method assumes that a SSPI context is already in a good shape.
        // For example it is either a fresh context or already authenticated context that needs renegotiation.
        //
        private Task ProcessAuthenticationAsync(bool isAsync = false, CancellationToken cancellationToken = default)
        {
            ThrowIfExceptional();

            if (NetSecurityTelemetry.AnyTelemetryEnabled())
            {
                return ProcessAuthenticationWithTelemetryAsync(isAsync, cancellationToken);
            }
            else
            {
                return isAsync ?
                    ForceAuthenticationAsync<AsyncReadWriteAdapter>(IsServer, null, cancellationToken) :
                    ForceAuthenticationAsync<SyncReadWriteAdapter>(IsServer, null, cancellationToken);
            }
        }

        private async Task ProcessAuthenticationWithTelemetryAsync(bool isAsync, CancellationToken cancellationToken)
        {
            long startingTimestamp;
            if (NetSecurityTelemetry.Log.IsEnabled())
            {
                NetSecurityTelemetry.Log.HandshakeStart(IsServer, _sslAuthenticationOptions.TargetHost);
                startingTimestamp = Stopwatch.GetTimestamp();
            }
            else
            {
                startingTimestamp = 0;
            }

            Activity? activity = NetSecurityTelemetry.StartActivity(this);
            Exception? exception = null;
            try
            {
                Task task = isAsync ?
                    ForceAuthenticationAsync<AsyncReadWriteAdapter>(IsServer, null, cancellationToken) :
                    ForceAuthenticationAsync<SyncReadWriteAdapter>(IsServer, null, cancellationToken);

                await task.ConfigureAwait(false);

                if (startingTimestamp is not 0)
                {
                    // SslStream could already have been disposed at this point, in which case _connectionOpenedStatus == ConnectionStatus.Disposed
                    // Make sure that we increment the open connection counter only if it is guaranteed to be decremented in dispose/finalize
                    bool connectionOpen = Interlocked.CompareExchange(ref _connectionOpenedStatus, ConnectionStatus.HandshakeCompleted, ConnectionStatus.NoHandshake) == ConnectionStatus.NoHandshake;
                    SslProtocols protocol = GetSslProtocolInternal();
                    NetSecurityTelemetry.Log.HandshakeCompleted(protocol, startingTimestamp, connectionOpen);
                }
            }
            catch (Exception ex)
            {
                exception = ex;
                if (startingTimestamp is not 0)
                {
                    NetSecurityTelemetry.Log.HandshakeFailed(IsServer, startingTimestamp, ex.Message);
                }

                throw;
            }
            finally
            {
                NetSecurityTelemetry.StopActivity(activity, exception, this);
            }
        }

        // - Loads the channel parameters
        // - Optionally verifies the Remote Certificate
        // - Sets HandshakeCompleted flag
        // - Sets the guarding event if other thread is waiting for
        //   handshake completion
        //
        // - Returns false if failed to verify the Remote Cert
        //
        private bool CompleteHandshake(ref ProtocolToken alertToken, out SslPolicyErrors sslPolicyErrors, out X509ChainStatusFlags chainStatus)
        {
            ProcessHandshakeSuccess();

            if (_nestedAuth != NestedState.StreamInUse)
            {
                Console.WriteLine("nested auth not in use");
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Ignoring unsolicited renegotiated certificate.");
                // ignore certificates received outside of handshake or requested renegotiation.
                sslPolicyErrors = SslPolicyErrors.None;
                chainStatus = X509ChainStatusFlags.NoError;
                return true;
            }

#if TARGET_ANDROID
            // On Android, the remote certificate verification can be invoked from Java TrustManager's callback
            // during the handshake process. If that has occurred, we shouldn't run the validation again and
            // return the existing validation result.
            //
            // The Java TrustManager callback is called only when the peer has a certificate. It's possible that
            // the peer didn't provide any certificate (for example when the peer is the client) and the validation
            // result hasn't been set. In that case we still need to run the verification at this point.
            if (TryGetRemoteCertificateValidationResult(out sslPolicyErrors, out chainStatus, ref alertToken, out bool isValid))
            {
                _handshakeCompleted = isValid;
                return isValid;
            }
#endif

            if (!VerifyRemoteCertificate(_sslAuthenticationOptions.CertValidationDelegate, _sslAuthenticationOptions.CertificateContext?.Trust, ref alertToken, out sslPolicyErrors, out chainStatus))
            {
                Console.WriteLine("remote cert validation failed");
                _handshakeCompleted = false;
                return false;
            }

            Console.WriteLine("handshake completed");
            _handshakeCompleted = true;
            return true;
        }

        private void CompleteHandshake(SslAuthenticationOptions sslAuthenticationOptions)
        {
            ProtocolToken alertToken = default;
            if (!CompleteHandshake(ref alertToken, out SslPolicyErrors sslPolicyErrors, out X509ChainStatusFlags chainStatus))
            {
                if (sslAuthenticationOptions!.CertValidationDelegate != null)
                {
                    // there may be some chain errors but the decision was made by custom callback. Details should be tracing if enabled.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.net_ssl_io_cert_custom_validation, null)));
                }
                else if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors && chainStatus != X509ChainStatusFlags.NoError)
                {
                    // We failed only because of chain and we have some insight.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.Format(SR.net_ssl_io_cert_chain_validation, chainStatus), null)));
                }
                else
                {
                    // Simple add sslPolicyErrors as crude info.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.Format(SR.net_ssl_io_cert_validation, sslPolicyErrors), null)));
                }
            }
        }

        //
        //  This is to reset auth state on remote side.
        //  If this write succeeds we will allow auth retrying.
        //
        private void SendAuthResetSignal(ReadOnlySpan<byte> alert, ExceptionDispatchInfo exception)
        {
            SetException(exception.SourceException);

            if (alert.Length == 0)
            {
                //
                // We don't have an alert to send so cannot retry and fail prematurely.
                //
                exception.Throw();
            }

            InnerStream.Write(alert);

            exception.Throw();
        }

        private async ValueTask WriteAsyncInternal<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            ThrowIfExceptionalOrNotAuthenticatedOrShutdown();

            if (buffer.Length == 0 && !SslStreamPal.CanEncryptEmptyMessage)
            {
                // If it's an empty message and the PAL doesn't support that, we're done.
                return;
            }

            if (Interlocked.Exchange(ref _nestedWrite, NestedState.StreamInUse) == NestedState.StreamInUse)
            {
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, "write"));
            }

            try
            {
                ValueTask t = buffer.Length < MaxDataSize ?
                    WriteSingleChunk<TIOAdapter>(buffer, cancellationToken) :
                    WriteAsyncChunked<TIOAdapter>(buffer, cancellationToken);
                await t.ConfigureAwait(false);
            }
            catch (Exception e)
            {
                if (e is IOException || (e is OperationCanceledException && cancellationToken.IsCancellationRequested))
                {
                    throw;
                }

                throw new IOException(SR.net_io_write, e);
            }
            finally
            {
                _nestedWrite = NestedState.StreamNotInUse;
            }
        }

        private async ValueTask WriteAsyncChunked<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            do
            {
                int chunkBytes = Math.Min(buffer.Length, MaxDataSize);
                await WriteSingleChunk<TIOAdapter>(buffer.Slice(0, chunkBytes), cancellationToken).ConfigureAwait(false);
                buffer = buffer.Slice(chunkBytes);
            } while (buffer.Length != 0);
        }

        //
        // This is to not depend on GC&SafeHandle class if the context is not needed anymore.
        //
        private void CloseInternal()
        {
            _exception = s_disposedSentinel;
            CloseContext();

            // Ensure a Read or Auth operation is not in progress,
            // block potential future read and auth operations since SslStream is disposing.
            // This leaves the _nestedRead = StreamDisposed and _nestedAuth = StreamDisposed, but that's ok, since
            // subsequent operations check the _exception sentinel first
            if (Interlocked.Exchange(ref _nestedRead, NestedState.StreamDisposed) == NestedState.StreamNotInUse &&
                Interlocked.Exchange(ref _nestedAuth, NestedState.StreamDisposed) == NestedState.StreamNotInUse)
            {
                _buffer.ReturnBuffer();
            }

            if (!_buffer.IsValid)
            {
                // Suppress finalizer since the read buffer was returned.
                GC.SuppressFinalize(this);
            }

            if (NetSecurityTelemetry.Log.IsEnabled())
            {
                // Set the status to disposed. If it was opened before, log ConnectionClosed
                if (Interlocked.Exchange(ref _connectionOpenedStatus, ConnectionStatus.Disposed) == ConnectionStatus.HandshakeCompleted)
                {
                    NetSecurityTelemetry.Log.ConnectionClosed(GetSslProtocolInternal());
                }
            }
        }

        private void SetException(Exception e)
        {
            Debug.Assert(e != null, $"Expected non-null Exception to be passed to {nameof(SetException)}");

            _exception ??= ExceptionDispatchInfo.Capture(e);

            CloseContext();
        }
    }
}
