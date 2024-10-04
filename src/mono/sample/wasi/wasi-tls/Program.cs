// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.CompilerServices;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Security;

public static class WasiMainWrapper
{
    public static async Task<int> MainAsync(string[] args)
    {
        var host = "example.com";
        var port = 443;
    
        //Thread.Sleep(1000);

        using var client = new TcpClient();
        await client.ConnectAsync(host, port);
        using var tcpStream = client.GetStream();
        using var sslStream = new SslStream(tcpStream);
        Console.WriteLine("Authenticating...");
        await sslStream.AuthenticateAsClientAsync(host);
        Console.WriteLine("Sending request...");
        await sslStream.WriteAsync(
            Encoding.UTF8.GetBytes(
                $"GET / HTTP/1.1\r\nhost: {host}:{port}\r\nconnection: close\r\n\r\n"
            )
        );
        var response = new System.IO.MemoryStream();
        await sslStream.CopyToAsync(response);
        Console.WriteLine(Encoding.UTF8.GetString(response.GetBuffer()));

        return 0;
    }

    public static int Main(string[] args)
    {
        return PollWasiEventLoopUntilResolved((Thread)null!, MainAsync(args));

        [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "PollWasiEventLoopUntilResolved")]
        static extern T PollWasiEventLoopUntilResolved<T>(Thread t, Task<T> mainTask);
    }

}
