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
        internal const bool StartMutualAuthAsAnonymous = false;
        internal const bool CanEncryptEmptyMessage = false;
        public static Exception GetException(SecurityStatusPal status)
        {
            return status.Exception ?? new Win32Exception((int)status.ErrorCode);
        }

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

        public static SafeFreeCredentials? AcquireCredentialsHandle(SslAuthenticationOptions _1, bool _2)
        {
            return null;
        }
    }
}
