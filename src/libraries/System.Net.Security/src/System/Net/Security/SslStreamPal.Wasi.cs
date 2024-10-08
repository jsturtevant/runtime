// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;

#pragma warning disable IDE0060

namespace System.Net.Security
{
    internal static class SslStreamPal
    {
        public static Exception GetException(SecurityStatusPal status)
        {
            return status.Exception ?? new Win32Exception((int)status.ErrorCode);
        }

        internal const bool StartMutualAuthAsAnonymous = false;
        internal const bool CanEncryptEmptyMessage = false;

        public static void VerifyPackageInfo()
        {
        }

        public static SecurityStatusPal SelectApplicationProtocol(
            SafeFreeCredentials? credentialsHandle,
            SafeDeleteSslContext? context,
            SslAuthenticationOptions sslAuthenticationOptions,
            ReadOnlySpan<byte> clientProtocols)
        {
            throw new PlatformNotSupportedException(nameof(SelectApplicationProtocol));
        }

        public static ProtocolToken AcceptSecurityContext(
            ref SafeFreeCredentials credential,
            ref SafeDeleteSslContext? context,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            return HandshakeInternal(ref context, inputBuffer, out consumed, sslAuthenticationOptions);
        }

        public static ProtocolToken InitializeSecurityContext(
            ref SafeFreeCredentials credential,
            ref SafeDeleteSslContext? context,
            string? targetName,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            return HandshakeInternal(ref context, inputBuffer, out consumed, sslAuthenticationOptions);
        }

        public static ProtocolToken Renegotiate(
            ref SafeFreeCredentials? credentialsHandle,
            ref SafeDeleteSslContext? context,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            // Wasi doesn't support renegotiation
            throw new PlatformNotSupportedException();
        }

        public static SafeFreeCredentials? AcquireCredentialsHandle(SslAuthenticationOptions _1, bool _2)
        {
            return null;
        }

        public static ProtocolToken EncryptMessage(
            SafeDeleteSslContext securityContext,
            ReadOnlyMemory<byte> input,
            int headerSize,
            int trailerSize)
        {
            ProtocolToken token = default;

            securityContext!.SslWrite(input.Span);
            securityContext!.ReadPendingWrites(ref token);

            token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.OK);

            return token;
        }

        public static SecurityStatusPal DecryptMessage(
            SafeDeleteSslContext securityContext,
            Span<byte> buffer,
            out int offset,
            out int count)
        {
            offset = 0;
            count = 0;

            try
            {
                securityContext!.Write(buffer);

                var read = securityContext!.SslRead(buffer);
                count = read;
                return new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
            }
            catch (Exception e)
            {
                return new SecurityStatusPal(SecurityStatusPalErrorCode.InternalError, e);
            }
        }

        public static ChannelBinding? QueryContextChannelBinding(
            SafeDeleteContext securityContext,
            ChannelBindingKind attribute)
        {
            // todo call finish handshake
            throw new PlatformNotSupportedException("TODO");
        }

        public static void QueryContextStreamSizes(
            SafeDeleteContext? securityContext,
            out StreamSizes streamSizes)
        {
            streamSizes = StreamSizes.Default;
        }

        public static void QueryContextConnectionInfo(
            SafeDeleteSslContext securityContext,
            ref SslConnectionInfo connectionInfo)
        {
            connectionInfo.UpdateSslConnectionInfo(securityContext);
        }

        public static bool TryUpdateClintCertificate(
            SafeFreeCredentials? _1,
            SafeDeleteSslContext? _2,
            SslAuthenticationOptions _3)
        {
            return false;
        }

        private static ProtocolToken HandshakeInternal(
            ref SafeDeleteSslContext? context,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            ProtocolToken token = default;
            consumed = 0;

            try
            {
                SafeDeleteSslContext? sslContext = (SafeDeleteSslContext?)context;

                if (context == null || context.IsInvalid)
                {
                    context = new SafeDeleteSslContext(sslAuthenticationOptions);
                    sslContext = context;
                }

                if (inputBuffer.Length > 0)
                {
                    sslContext!.Write(inputBuffer);
                }
                consumed = inputBuffer.Length;

                token.Status = sslContext!.FinishHandShake(ref token);

                return token;
            }
            catch (Exception exc)
            {
                token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.InternalError, exc);
                return token;
            }
        }

        public static SecurityStatusPal ApplyAlertToken(
            SafeDeleteContext? securityContext,
            TlsAlertType alertType,
            TlsAlertMessage alertMessage)
        {
            // Wasi doesn't support sending alerts
            return new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
        }

        public static SecurityStatusPal ApplyShutdownToken(
            SafeDeleteSslContext securityContext)
        {
            // not specified yet
            throw new PlatformNotSupportedException("TODO");
        }
    }
}
