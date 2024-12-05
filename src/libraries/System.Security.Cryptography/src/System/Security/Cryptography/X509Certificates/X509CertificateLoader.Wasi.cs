// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Formats.Asn1;
using System.IO;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        private static partial ICertificatePal LoadCertificatePal(ReadOnlySpan<byte> data)
        {
            return new WasiCertificatePal(data);
        }

        private static partial ICertificatePal LoadCertificatePalFromFile(string path)
        {
            throw new PlatformNotSupportedException();
        }

        static partial void ValidatePlatformKeyStorageFlags(X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException();
        }

        private static partial Pkcs12Return LoadPkcs12(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }

        private static partial X509Certificate2Collection LoadPkcs12Collection(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }
    }
}
