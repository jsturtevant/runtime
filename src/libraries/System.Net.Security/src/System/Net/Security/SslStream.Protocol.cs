// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security
{
    public partial class SslStream
    {
        // These are the MAX encrypt buffer output sizes, not the actual sizes.
        private int _headerSize = 5; //ATTN must be set to at least 5 by default
        private int _trailerSize = 16;
        private int _maxDataSize = 16354;


        private X509Certificate2? _remoteCertificate;

        private SslConnectionInfo _connectionInfo;



        private static readonly Oid s_serverAuthOid = new Oid("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.1");
        private static readonly Oid s_clientAuthOid = new Oid("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.2");

        /*++
           ProcessHandshakeSuccess -
              Called on successful completion of Handshake -
              used to set header/trailer sizes for encryption use

           Fills in the information about established protocol
       --*/
        internal void ProcessHandshakeSuccess()
        {
            SslStreamPal.QueryContextStreamSizes(_securityContext!, out StreamSizes streamSizes);

            _headerSize = streamSizes.Header;
            _trailerSize = streamSizes.Trailer;
            _maxDataSize = streamSizes.MaximumMessage;
            Debug.Assert(_maxDataSize > 0);

            SslStreamPal.QueryContextConnectionInfo(_securityContext!, ref _connectionInfo);
#if DEBUG
            if (NetEventSource.Log.IsEnabled())
            {
                // This keeps the property alive only for tests via reflection
                // Otherwise it could be optimized out as it is not used by production code.
                NetEventSource.Info(this, $"TLS resumed {_connectionInfo.TlsResumed}");
            }
#endif
        }


        //
        // Protocol properties
        //
        //   LocalServerCertificate - local certificate for server mode channel
        //   LocalClientCertificate - selected certificated used in the client channel mode otherwise null
        //   IsRemoteCertificateAvailable - true if the remote side has provided a certificate
        //   HeaderSize             - Header & trailer sizes used in the TLS stream
        //   TrailerSize -
        //
        internal X509Certificate? LocalServerCertificate
        {
            get
            {
                return _sslAuthenticationOptions.CertificateContext?.TargetCertificate;
            }
        }

        internal bool IsRemoteCertificateAvailable
        {
            get
            {
                return _remoteCertificate != null;
            }
        }

        internal bool IsValidContext
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                return !(_securityContext == null || _securityContext.IsInvalid);
            }
        }

        internal bool RemoteCertRequired
        {
            get
            {
                return _sslAuthenticationOptions.RemoteCertRequired;
            }
        }

        internal ChannelBinding? GetChannelBinding(ChannelBindingKind kind)
        {
            ChannelBinding? result = null;
            if (_securityContext != null)
            {
                result = SslStreamPal.QueryContextChannelBinding(_securityContext, kind);
            }

            return result;
        }

        internal int MaxDataSize
        {
            get
            {
                return _maxDataSize;
            }
        }

        /*++
                VerifyRemoteCertificate - Validates the content of a Remote Certificate

                checkCRL if true, checks the certificate revocation list for validity.
                checkCertName, if true checks the CN field of the certificate
            --*/

        //This method validates a remote certificate.
        internal bool VerifyRemoteCertificate(RemoteCertificateValidationCallback? remoteCertValidationCallback, SslCertificateTrust? trust, ref ProtocolToken alertToken, out SslPolicyErrors sslPolicyErrors, out X509ChainStatusFlags chainStatus)
        {
            sslPolicyErrors = SslPolicyErrors.None;
            chainStatus = X509ChainStatusFlags.NoError;

            // We don't catch exceptions in this method, so it's safe for "accepted" be initialized with true.
            bool success = false;
            X509Chain? chain = null;

            try
            {
                X509Certificate2? certificate = CertificateValidationPal.GetRemoteCertificate(_securityContext, ref chain, _sslAuthenticationOptions.CertificateChainPolicy);
                if (_remoteCertificate != null &&
                    certificate != null &&
                    certificate.RawDataMemory.Span.SequenceEqual(_remoteCertificate.RawDataMemory.Span))
                {
                    // This is renegotiation or TLS 1.3 and the certificate did not change.
                    // There is no reason to process callback again as we already established trust.
                    certificate.Dispose();
                    return true;
                }

                _remoteCertificate = certificate;
                if (_remoteCertificate == null)
                {
                    if (NetEventSource.Log.IsEnabled() && RemoteCertRequired) NetEventSource.Error(this, $"Remote certificate required, but no remote certificate received");
                    sslPolicyErrors |= SslPolicyErrors.RemoteCertificateNotAvailable;
                }
                else
                {
                    chain ??= new X509Chain();

                    if (_sslAuthenticationOptions.CertificateChainPolicy != null)
                    {
                        chain.ChainPolicy = _sslAuthenticationOptions.CertificateChainPolicy;
                    }
                    else
                    {
                        chain.ChainPolicy.RevocationMode = _sslAuthenticationOptions.CertificateRevocationCheckMode;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                        if (trust != null)
                        {
                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            if (trust._store != null)
                            {
                                chain.ChainPolicy.CustomTrustStore.AddRange(trust._store.Certificates);
                            }
                            if (trust._trustList != null)
                            {
                                chain.ChainPolicy.CustomTrustStore.AddRange(trust._trustList);
                            }
                        }
                    }

                    // set ApplicationPolicy unless already provided.
                    if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
                    {
                        // Authenticate the remote party: (e.g. when operating in server mode, authenticate the client).
                        chain.ChainPolicy.ApplicationPolicy.Add(_sslAuthenticationOptions.IsServer ? s_clientAuthOid : s_serverAuthOid);
                    }

                    sslPolicyErrors |= CertificateValidationPal.VerifyCertificateProperties(
                        _securityContext!,
                        chain,
                        _remoteCertificate,
                        _sslAuthenticationOptions.CheckCertName,
                        _sslAuthenticationOptions.IsServer,
                        TargetHostNameHelper.NormalizeHostName(_sslAuthenticationOptions.TargetHost));
                }

                if (remoteCertValidationCallback != null)
                {
                    success = remoteCertValidationCallback(this, _remoteCertificate, chain, sslPolicyErrors);
                }
                else
                {
                    if (!RemoteCertRequired)
                    {
                        sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNotAvailable;
                    }

                    success = (sslPolicyErrors == SslPolicyErrors.None);
                }

                if (NetEventSource.Log.IsEnabled())
                {
                    LogCertificateValidation(remoteCertValidationCallback, sslPolicyErrors, success, chain!);
                    NetEventSource.Info(this, $"Cert validation, remote cert = {_remoteCertificate}");
                }

                if (!success)
                {
                    CreateFatalHandshakeAlertToken(sslPolicyErrors, chain!, ref alertToken);
                    if (chain != null)
                    {
                        foreach (X509ChainStatus status in chain.ChainStatus)
                        {
                            chainStatus |= status.Status;
                        }
                    }
                }
            }
            finally
            {
                // At least on Win2k server the chain is found to have dependencies on the original cert context.
                // So it should be closed first.

                if (chain != null)
                {
                    int elementsCount = chain.ChainElements.Count;
                    for (int i = 0; i < elementsCount; i++)
                    {
                        chain.ChainElements[i].Certificate.Dispose();
                    }

                    chain.Dispose();
                }
            }

            return success;
        }

        private void CreateFatalHandshakeAlertToken(SslPolicyErrors sslPolicyErrors, X509Chain chain, ref ProtocolToken alertToken)
        {
            TlsAlertMessage alertMessage;

            switch (sslPolicyErrors)
            {
                case SslPolicyErrors.RemoteCertificateChainErrors:
                    alertMessage = GetAlertMessageFromChain(chain);
                    break;
                case SslPolicyErrors.RemoteCertificateNameMismatch:
                    alertMessage = TlsAlertMessage.BadCertificate;
                    break;
                case SslPolicyErrors.RemoteCertificateNotAvailable:
                default:
                    alertMessage = TlsAlertMessage.CertificateUnknown;
                    break;
            }

            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Info(this, $"alertMessage:{alertMessage}");

            SecurityStatusPal status;
            status = SslStreamPal.ApplyAlertToken(_securityContext, TlsAlertType.Fatal, alertMessage);

            if (status.ErrorCode != SecurityStatusPalErrorCode.OK)
            {
                if (NetEventSource.Log.IsEnabled())
                    NetEventSource.Info(this, $"ApplyAlertToken() returned {status.ErrorCode}");

                if (status.Exception != null)
                {
                    ExceptionDispatchInfo.Throw(status.Exception);
                }
            }

            alertToken = GenerateAlertToken();
        }

        private ProtocolToken CreateShutdownToken()
        {
            SecurityStatusPal status;
            status = SslStreamPal.ApplyShutdownToken(_securityContext!);

            if (status.ErrorCode != SecurityStatusPalErrorCode.OK)
            {
                if (NetEventSource.Log.IsEnabled())
                    NetEventSource.Info(this, $"ApplyAlertToken() returned {status.ErrorCode}");

                if (status.Exception != null)
                {
                    ExceptionDispatchInfo.Throw(status.Exception);
                }

                return default;
            }

            return GenerateToken(default, out _);
        }

        private static TlsAlertMessage GetAlertMessageFromChain(X509Chain chain)
        {
            foreach (X509ChainStatus chainStatus in chain.ChainStatus)
            {
                if (chainStatus.Status == X509ChainStatusFlags.NoError)
                {
                    continue;
                }

                if ((chainStatus.Status &
                    (X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain |
                     X509ChainStatusFlags.Cyclic)) != 0)
                {
                    return TlsAlertMessage.UnknownCA;
                }

                if ((chainStatus.Status &
                    (X509ChainStatusFlags.Revoked | X509ChainStatusFlags.OfflineRevocation)) != 0)
                {
                    return TlsAlertMessage.CertificateRevoked;
                }

                if ((chainStatus.Status &
                    (X509ChainStatusFlags.CtlNotTimeValid | X509ChainStatusFlags.NotTimeNested |
                     X509ChainStatusFlags.NotTimeValid)) != 0)
                {
                    return TlsAlertMessage.CertificateExpired;
                }

                if ((chainStatus.Status & X509ChainStatusFlags.CtlNotValidForUsage) != 0)
                {
                    return TlsAlertMessage.UnsupportedCert;
                }

                if ((chainStatus.Status &
                    (X509ChainStatusFlags.CtlNotSignatureValid | X509ChainStatusFlags.InvalidExtension |
                     X509ChainStatusFlags.NotSignatureValid | X509ChainStatusFlags.InvalidPolicyConstraints) |
                     X509ChainStatusFlags.NoIssuanceChainPolicy | X509ChainStatusFlags.NotValidForUsage) != 0)
                {
                    return TlsAlertMessage.BadCertificate;
                }

                // All other errors:
                return TlsAlertMessage.CertificateUnknown;
            }

            return TlsAlertMessage.BadCertificate;
        }

        private void LogCertificateValidation(RemoteCertificateValidationCallback? remoteCertValidationCallback, SslPolicyErrors sslPolicyErrors, bool success, X509Chain chain)
        {
            if (!NetEventSource.Log.IsEnabled())
                return;

            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                NetEventSource.Log.RemoteCertificateError(this, SR.net_log_remote_cert_has_errors);
                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
                {
                    NetEventSource.Log.RemoteCertificateError(this, SR.net_log_remote_cert_not_available);
                }

                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    NetEventSource.Log.RemoteCertificateError(this, SR.net_log_remote_cert_name_mismatch);
                }

                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                {
                    string chainStatusString = "ChainStatus: ";
                    foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                    {
                        chainStatusString += "\t" + chainStatus.StatusInformation;
                    }
                    NetEventSource.Log.RemoteCertificateError(this, chainStatusString);
                }
            }

            if (success)
            {
                if (remoteCertValidationCallback != null)
                {
                    NetEventSource.Log.RemoteCertDeclaredValid(this);
                }
                else
                {
                    NetEventSource.Log.RemoteCertHasNoErrors(this);
                }
            }
            else
            {
                if (remoteCertValidationCallback != null)
                {
                    NetEventSource.Log.RemoteCertUserDeclaredInvalid(this);
                }
            }
        }

        //
        // Get certificate_authorities list, according to RFC 5246, Section 7.4.4.
        // Used only by client SSL code, never returns null.
        //
        private string[] GetRequestCertificateAuthorities()
        {
            string[] issuers = Array.Empty<string>();

            if (IsValidContext)
            {
                issuers = CertificateValidationPal.GetRequestCertificateAuthorities(_securityContext!);
            }
            return issuers;
        }
    }

    // ProtocolToken - used to process and handle the return codes from the SSPI wrapper
    internal struct ProtocolToken
    {
        internal SecurityStatusPal Status;
        internal byte[]? Payload;
        internal int Size;
        internal bool RentBuffer;

        internal bool Failed
        {
            get
            {
                return ((Status.ErrorCode != SecurityStatusPalErrorCode.OK) && (Status.ErrorCode != SecurityStatusPalErrorCode.ContinueNeeded));
            }
        }

        internal bool Done
        {
            get
            {
                return (Status.ErrorCode == SecurityStatusPalErrorCode.OK);
            }
        }

        internal bool Renegotiate
        {
            get
            {
                return (Status.ErrorCode == SecurityStatusPalErrorCode.Renegotiate);
            }
        }

        internal bool CloseConnection
        {
            get
            {
                return (Status.ErrorCode == SecurityStatusPalErrorCode.ContextExpired);
            }
        }
        internal void SetPayload(ReadOnlySpan<byte> payload)
        {
            Debug.Assert(Payload == null);
            Size = payload.Length;

            if (Size > 0)
            {
                Payload = RentBuffer ? ArrayPool<byte>.Shared.Rent(Size) : new byte[Size];
                payload.CopyTo(new Span<byte>(Payload, 0, Size));
            }
        }

        internal void EnsureAvailableSpace(int size)
        {
            if (Available >= size)
            {
                return;
            }

            var oldPayload = Payload;

            Payload = RentBuffer ? ArrayPool<byte>.Shared.Rent(Size + size) : new byte[Size + size];
            if (oldPayload != null)
            {
                oldPayload.AsSpan<byte>().CopyTo(Payload);
                if (RentBuffer)
                {
                    ArrayPool<byte>.Shared.Return(oldPayload);
                }
            }
        }

        internal int Available => Payload == null ? 0 : Payload.Length - Size;
        internal Span<byte> AvailableSpan => Payload == null ? Span<byte>.Empty : new Span<byte>(Payload, Size, Available);

        internal ReadOnlyMemory<byte> AsMemory() => new ReadOnlyMemory<byte>(Payload, 0, Size);

        internal void ReleasePayload()
        {
            Debug.Assert(Payload != null || Size == 0);

            byte[]? toReturn = Payload;
            Payload = null;
            Size = 0;
            if (RentBuffer && toReturn != null)
            {
                ArrayPool<byte>.Shared.Return(toReturn);
            }
        }

        internal Exception? GetException()
        {
            // If it's not done, then there's got to be an error, even if it's
            // a Handshake message up, and we only have a Warning message.
            return Done ? null : SslStreamPal.GetException(Status);
        }
    }
}
