// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class WasiCertificatePal : ICertificatePal
    {
        private CertificateData _certData;
        private byte[] _rawData;

        internal WasiCertificatePal(ReadOnlySpan<byte> rawData)
        {
            _rawData = rawData.ToArray();
        }

        public string Issuer
        {
            get
            {
                EnsureCertificateData();
                return _certData.IssuerName;
            }
        }

        public string Subject
        {
            get
            {
                EnsureCertificateData();
                return _certData.SubjectName;
            }
        }

        public bool HasPrivateKey => false;

        public IntPtr Handle => throw new PlatformNotSupportedException(nameof(Handle));

        public string LegacyIssuer => IssuerName.Decode(X500DistinguishedNameFlags.None);

        public string LegacySubject => SubjectName.Decode(X500DistinguishedNameFlags.None);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 is required for Compat")]
        public byte[] Thumbprint
        {
            get
            {
                EnsureCertificateData();
                return SHA1.HashData(_certData.RawData);
            }
        }

        public string KeyAlgorithm
        {
            get
            {
                EnsureCertificateData();
                return _certData.PublicKeyAlgorithm.AlgorithmId!;
            }
        }

        public byte[] KeyAlgorithmParameters
        {
            get
            {
                EnsureCertificateData();
                return _certData.PublicKeyAlgorithm.Parameters;
            }
        }

        public byte[] PublicKeyValue
        {
            get
            {
                EnsureCertificateData();
                return _certData.PublicKey;
            }
        }

        public byte[] SubjectPublicKeyInfo
        {
            get
            {
                EnsureCertificateData();
                return _certData.SubjectPublicKeyInfo;
            }
        }

        public byte[] SerialNumber
        {
            get
            {
                EnsureCertificateData();
                return _certData.SerialNumber;
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                EnsureCertificateData();
                return _certData.SignatureAlgorithm.AlgorithmId!;
            }
        }

        public DateTime NotAfter
        {
            get
            {
                EnsureCertificateData();
                return _certData.NotAfter.ToLocalTime();
            }
        }

        public DateTime NotBefore
        {
            get
            {
                EnsureCertificateData();
                return _certData.NotBefore.ToLocalTime();
            }
        }

        public byte[] RawData => _rawData;

        public int Version
        {
            get
            {
                EnsureCertificateData();
                return _certData.Version + 1;
            }
        }

        public bool Archived
        {
            get { return false; }
            set
            {
                throw new PlatformNotSupportedException(
                    SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, nameof(Archived)));
            }
        }

        public string FriendlyName
        {
            get { return ""; }
            set
            {
                throw new PlatformNotSupportedException(
                  SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, nameof(FriendlyName)));
            }
        }

        public X500DistinguishedName SubjectName
        {
            get
            {
                EnsureCertificateData();
                return _certData.Subject;
            }
        }

        public X500DistinguishedName IssuerName
        {
            get
            {
                EnsureCertificateData();
                return _certData.Issuer;
            }
        }

        public PolicyData GetPolicyData()
        {
            EnsureCertificateData();
            PolicyData policyData = default;
            foreach (X509Extension extension in _certData.Extensions)
            {
                switch (extension.Oid!.Value)
                {
                    case Oids.ApplicationCertPolicies:
                        policyData.ApplicationCertPolicies = extension.RawData;
                        break;
                    case Oids.CertPolicies:
                        policyData.CertPolicies = extension.RawData;
                        break;
                    case Oids.CertPolicyMappings:
                        policyData.CertPolicyMappings = extension.RawData;
                        break;
                    case Oids.CertPolicyConstraints:
                        policyData.CertPolicyConstraints = extension.RawData;
                        break;
                    case Oids.EnhancedKeyUsage:
                        policyData.EnhancedKeyUsage = extension.RawData;
                        break;
                    case Oids.InhibitAnyPolicyExtension:
                        policyData.InhibitAnyPolicyExtension = extension.RawData;
                        break;
                }
            }

            return policyData;
        }

        public IEnumerable<X509Extension> Extensions
        {
            get
            {
                EnsureCertificateData();
                return _certData.Extensions;
            }
        }

        public RSA? GetRSAPrivateKey()
        {
            throw new PlatformNotSupportedException(nameof(GetRSAPrivateKey));
        }

        public DSA? GetDSAPrivateKey()
        {
            throw new PlatformNotSupportedException(nameof(GetDSAPrivateKey));
        }

        public ECDsa? GetECDsaPrivateKey()
        {
            throw new PlatformNotSupportedException(nameof(GetECDsaPrivateKey));
        }

        public ECDiffieHellman? GetECDiffieHellmanPrivateKey()
        {
            throw new PlatformNotSupportedException(nameof(GetECDiffieHellmanPrivateKey));
        }

        public ICertificatePal CopyWithPrivateKey(DSA privateKey)
        {
            throw new PlatformNotSupportedException(nameof(CopyWithPrivateKey));
        }

        public ICertificatePal CopyWithPrivateKey(ECDsa privateKey)
        {
            throw new PlatformNotSupportedException(nameof(CopyWithPrivateKey));
        }

        public ICertificatePal CopyWithPrivateKey(ECDiffieHellman privateKey)
        {
            throw new PlatformNotSupportedException(nameof(CopyWithPrivateKey));
        }

        public ICertificatePal CopyWithPrivateKey(RSA privateKey)
        {
            throw new PlatformNotSupportedException(nameof(CopyWithPrivateKey));
        }

        public string GetNameInfo(X509NameType nameType, bool forIssuer)
        {
            EnsureCertificateData();
            return _certData.GetNameInfo(nameType, forIssuer);
        }

        public void AppendPrivateKeyInfo(StringBuilder sb)
        {
            throw new PlatformNotSupportedException(nameof(AppendPrivateKeyInfo));
        }

        public byte[] Export(X509ContentType contentType, SafePasswordHandle password)
        {
            using (IExportPal storePal = StorePal.FromCertificate(this))
            {
                byte[]? exported = storePal.Export(contentType, password);
                Debug.Assert(exported != null);
                return exported;
            }
        }

        private void EnsureCertificateData()
        {
            if (!_certData.Equals(default(CertificateData)))
                return;

            _certData = new CertificateData(_rawData);
        }

        public void Dispose()
        {
            // nothing to do
        }

    }
}
