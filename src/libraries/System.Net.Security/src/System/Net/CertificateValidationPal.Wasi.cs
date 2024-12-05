// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace System.Net
{
    internal static partial class CertificateValidationPal
    {
        #pragma warning disable IDE0060
        internal static SslPolicyErrors VerifyCertificateProperties(
            SafeDeleteContext _securityContext,
            X509Chain _chain,
            X509Certificate2? remoteCertificate,
            bool _checkCertName,
            bool _isServer /*isServer*/,
            string? _hostName)
        {
            if (remoteCertificate == null)
                return SslPolicyErrors.RemoteCertificateNotAvailable;

            //todo do more validations?
            return SslPolicyErrors.None;
        }
        #pragma warning restore IDE0060

        //
        // Extracts a remote certificate upon request.
        //

        private static X509Certificate2? GetRemoteCertificate(
            SafeDeleteContext? securityContext,
            bool retrieveChainCertificates,
            ref X509Chain? _,
            X509ChainPolicy? __)
        {
            var sslContext = ((SafeDeleteSslContext?)securityContext);
            if (sslContext == null || sslContext.ClientConnection == null)
                return null;

            var remoteIdentity = sslContext.ClientConnection.ServerIdentity();
            if (remoteIdentity is null)
                return null;

            var remoteCertChain = remoteIdentity.ExportX509Chain();
            if (remoteCertChain.Count == 0) {
                return null;
            }
            var cert =  X509CertificateLoader.LoadCertificate(remoteCertChain.First().ToArray());
            if (retrieveChainCertificates) {
                Console.WriteLine("WARNING: not implemented");
                // requires some changes in rust-native-tls
                //throw new NotSupportedException("todo: certchain implemented on wasi");
            }
            return cert;
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
