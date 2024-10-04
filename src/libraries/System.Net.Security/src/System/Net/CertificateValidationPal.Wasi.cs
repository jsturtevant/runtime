// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace System.Net
{
    internal static partial class CertificateValidationPal
    {
        internal static SslPolicyErrors VerifyCertificateProperties(
            SafeDeleteContext securityContext,
            X509Chain chain,
            X509Certificate2? remoteCertificate,
            bool checkCertName,
            bool _ /*isServer*/,
            string? hostName)
        {
            throw new NotImplementedException(nameof(VerifyCertificateProperties));
        }

        //
        // Extracts a remote certificate upon request.
        //

        private static X509Certificate2? GetRemoteCertificate(
            SafeDeleteContext? securityContext,
            bool retrieveChainCertificates,
            ref X509Chain? chain,
            X509ChainPolicy? chainPolicy)
        {
            throw new NotImplementedException(nameof(GetRemoteCertificate));
        }

        // Check if the local certificate has been sent to the peer during the handshake.
        internal static bool IsLocalCertificateUsed(SafeFreeCredentials? _, SafeDeleteContext? securityContext)
        {
            throw new NotImplementedException(nameof(IsLocalCertificateUsed));
        }

        //
        // Used only by client SSL code, never returns null.
        //
        internal static string[] GetRequestCertificateAuthorities(SafeDeleteContext securityContext)
        {
            throw new NotImplementedException(nameof(GetRequestCertificateAuthorities));
        }

        private static X509Store OpenStore(StoreLocation storeLocation)
        {
            throw new NotImplementedException(nameof(OpenStore));
        }
    }
}
