// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System;
using System.IO;
using System.Runtime;

namespace System.Net.Security
{
    public partial class SslStream
    {
        internal sealed class WasiProxy : IDisposable
        {

            private readonly Stream _cipherStream;
            //private Stream? plainStream;

            public WasiProxy(Stream stream)
            {
                _cipherStream = stream;
            }

            public Stream Stream => _cipherStream;

            public void Dispose()
            {
                _cipherStream.Dispose();
                //plainStream?.Dispose();
            }

        }


    }
}
