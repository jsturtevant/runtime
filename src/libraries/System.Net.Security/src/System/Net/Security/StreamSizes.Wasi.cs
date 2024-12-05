// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net
{
    internal partial struct StreamSizes
    {
        // TODO: what is appropriate for wasi?  does it care?
        public static StreamSizes Default => new StreamSizes { MaximumMessage = 32 * 1024 };
    }
}
