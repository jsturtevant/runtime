// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using WasiTlsWorld;
using WasiTlsWorld.wit.imports.wasi.io.v0_2_0;
using WasiTlsWorld.wit.imports.wasi.sockets.v0_2_0;


namespace System.Net
{
    internal sealed class SafeDeleteSslContext : SafeDeleteContext
    {
        private ITls.ClientConnection? clientConnection;
        private Stream innerStream;
        private SslAuthenticationOptions _authOptions;
        private Stream? tlsStream;

        public SafeDeleteSslContext(SslAuthenticationOptions authOptions, Stream stream)
            : base(IntPtr.Zero)
        {
            innerStream = stream;
            _authOptions = authOptions;
        }

        public override bool IsInvalid => clientConnection == null;

        internal async Task AuthenticateAsync(){
            // We need to create two different ends to create a stream
            // The host implementation of makepipe creates a channel with a receive and send side which are returned here
            // The host will wire up the host sides to the SSL context and we use the other sides to read/write to the
            // ssl context.
            // componentWrite will end up writing to the SSL context on the host
            // componentRead will read output from SSL Context
            // The pipes here are initially created for the handshake process
            // and different read/write endpoints will be returned once the handshake is complete.
            (IStreams.InputStream hostTlsRead, IStreams.OutputStream componentWrite) = TlsInterop.MakePipe();
            (IStreams.InputStream componentRead, IStreams.OutputStream hostTlsWrite) = TlsInterop.MakePipe();

            WasiStream hostProxy = new WasiStream(componentRead, componentWrite);

            // kick this off so stream write to each other
            Console.WriteLine("copy pipes...");
            _ = hostProxy.CopyToAsync(innerStream);
            Console.WriteLine("copy pipes2...");
            _ = innerStream.CopyToAsync(hostProxy);

            Console.WriteLine("call finish TLS handshake...");
            clientConnection = new ITls.ClientConnection(hostTlsRead, hostTlsWrite);
            using var future = ITls.ClientHandshake.Finish(
                clientConnection.Connect(_authOptions.TargetHost)
            );

            while (true)
            {
                Console.WriteLine("Waiting for future...");
                var result = future.Get();
                if (result is not null)
                {
                    var inner = (
                        (Result<Result<(IStreams.InputStream, IStreams.OutputStream), None>, None>)
                            result!
                    ).AsOk;
                    if (inner.IsOk)
                    {
                        var (input, output) = inner.AsOk;
                        tlsStream = new WasiStream(input, output);
                        break;
                    }
                    else
                    {
                        throw new Exception("TLS handshake failed");
                    }
                }
                else
                {
                    await WasiInterop.RegisterWasiPollable(future.Subscribe(), CancellationToken.None).ConfigureAwait(false);
                }
            }
        }

         public new void Dispose()
        {
            Dispose(true);
        }

        public async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default
        )
        {
            await tlsStream!.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default
        )
        {
            return await tlsStream!.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            innerStream.Dispose();
            tlsStream?.Dispose();
        }

        public ITls.ClientConnection? ClientConnection => this.clientConnection;
    }

    internal static class WasiInterop
    {
        internal static Task RegisterWasiPollable(IPoll.Pollable pollable, CancellationToken cancellationToken)
        {
            var handle = pollable.Handle;

            // this will effectively neutralize Dispose() of the Pollable()
            // because in the CoreLib we create another instance, which will dispose it
            pollable.Handle = 0;
            GC.SuppressFinalize(pollable);

            return CallRegisterWasiPollableHandle((Thread)null!, handle, true, cancellationToken);

            [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "RegisterWasiPollableHandle")]
            static extern Task CallRegisterWasiPollableHandle(Thread t, int handle, bool ownsPollable, CancellationToken cancellationToken);
        }
    }

    public class WasiStream : Stream
    {
        internal IStreams.InputStream input;
        internal IStreams.OutputStream output;
        private int offset;
        private byte[]? buffer;
        private bool closed;

        internal WasiStream(IStreams.InputStream input, IStreams.OutputStream output)
        {
            this.input = input;
            this.output = output;
        }
        public bool Connected  => this.closed;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotImplementedException();
        public override long Position
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        public new void Dispose()
        {
            Dispose(true);
        }

        protected override void Dispose(bool disposing)
        {
            input.Dispose();
            output.Dispose();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void Flush()
        {
            // ignore
        }

        public override void SetLength(long length)
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int length)
        {
           throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }

        public override async Task<int> ReadAsync(
            byte[] bytes,
            int offset,
            int length,
            CancellationToken cancellationToken
        )
        {
            while (true)
            {
                if (closed)
                {
                    return 0;
                }
                else if (this.buffer == null)
                {
                    try
                    {
                        // TODO: should we add a special case to the bindings generator
                        // to allow passing a buffer to IStreams.InputStream.Read and
                        // avoid the extra copy?
                        var result = input.Read(16 * 1024);
                        var buffer = result;
                        if (buffer.Length == 0)
                        {
                            Console.WriteLine("read wait...");
                            await WasiInterop.RegisterWasiPollable(input.Subscribe(), cancellationToken).ConfigureAwait(false);
                        }
                        else
                        {
                            this.buffer = buffer;
                            this.offset = 0;
                        }
                    }
                    catch (WitException e)
                    {
                        var value = (IStreams.StreamError)e.Value;
                        if (value.Tag == IStreams.StreamError.CLOSED)
                        {
                            closed = true;
                            return 0;
                        }
                        else
                        {
                            throw new Exception(
                                $"read error: {value.AsLastOperationFailed.ToDebugString()}"
                            );
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Copy buffer...");
                    var min = Math.Min(this.buffer.Length - this.offset, length);
                    Array.Copy(this.buffer, this.offset, bytes, offset, min);
                    if (min < this.buffer.Length - this.offset)
                    {
                        this.offset += min;
                    }
                    else
                    {
                        this.buffer = null;
                    }
                    return min;
                }
            }
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default
        )
        {
            // TODO: avoid copy when possible and use ArrayPool when not
            var dst = new byte[buffer.Length];
#pragma warning disable CA1835
            var result = await ReadAsync(dst, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
#pragma warning restore CA1835
            new ReadOnlySpan<byte>(dst, 0, result).CopyTo(buffer.Span);
            return result;
        }

        public override async Task WriteAsync(
            byte[] bytes,
            int offset,
            int length,
            CancellationToken cancellationToken
        )
        {
            var limit = offset + length;
            var flushing = false;
            while (true)
            {
                int count;
                try
                {
                    count = (int)output.CheckWrite();
                }
                catch (WitException e)
                {
                    throw ConvertException(e);
                }
                if (count == 0)
                {
                    await WasiInterop.RegisterWasiPollable(output.Subscribe(), cancellationToken).ConfigureAwait(false);
                }
                else if (offset == limit)
                {
                    if (flushing)
                    {
                        return;
                    }
                    else
                    {
                        output.Flush();
                        flushing = true;
                    }
                }
                else
                {
                    var min = Math.Min(count, limit - offset);
                    if (offset == 0 && min == bytes.Length)
                    {
                        try
                        {
                            output.Write(bytes);
                        }
                        catch (WitException e)
                        {
                            throw ConvertException(e);
                        }
                    }
                    else
                    {
                        // TODO: is there a more efficient option than copying here?
                        // Do we need to change the binding generator to accept
                        // e.g. `Span`s?
                        var copy = new byte[min];
                        Array.Copy(bytes, offset, copy, 0, min);
                        output.Write(copy);
                    }
                    offset += min;
                }
            }
        }

        private static Exception ConvertException(WitException e)
        {
            var value = (IStreams.StreamError)e.Value;
            if (value.Tag == IStreams.StreamError.CLOSED)
            {
                return new Exception("write error: stream closed unexpectedly");
            }
            else
            {
                return new Exception($"write error: {value.AsLastOperationFailed.ToDebugString()}");
            }
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default
        )
        {
            // TODO: avoid copy when possible and use ArrayPool when not
            var copy = new byte[buffer.Length];
            buffer.Span.CopyTo(copy);
            return new ValueTask(WriteAsync(copy, 0, buffer.Length, cancellationToken));
        }
    }

}
