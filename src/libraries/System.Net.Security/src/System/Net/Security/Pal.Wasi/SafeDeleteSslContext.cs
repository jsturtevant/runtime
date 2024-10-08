// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
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
        private SslStream.WasiProxy cipherStream { get; }
        private ITls.ClientHandshake clientConnection { get; }

        public SafeDeleteSslContext(SslAuthenticationOptions authOptions)
            : base(IntPtr.Zero)
        {
            cipherStream = authOptions.SslStreamProxy
                ?? throw new ArgumentNullException(nameof(authOptions.SslStreamProxy));

            IStreams.InputStream cipherInput;
            IStreams.OutputStream cipherOutput;
            var (inputA, outputA) = TlsInterop.MakePipe();
            var (inputB, outputB) = TlsInterop.MakePipe();
            cipherInput = inputA;
            cipherOutput = outputB;
            var proxy = new WasiStream(inputB, outputA);
            _ = proxy.CopyToAsync(cipherStream.Stream);
            _ = cipherStream.Stream.CopyToAsync(proxy);

            clientConnection = new ITls.ClientConnection(cipherInput, cipherOutput).Connect(authOptions.TargetHost);
            //todo could configurat all the variaous options here

        }

        public override bool IsInvalid => true;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
    internal static class WasiInterop
    {
        public static Task RegisterWasiPollable(IPoll.Pollable pollable, CancellationToken cancellationToken)
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

    internal sealed class WasiStream : Stream
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
        public bool Connected => this.closed;

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
                            await WasiInterop
                                .RegisterWasiPollable(input.Subscribe(), cancellationToken)
                                .ConfigureAwait(false);
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
            var result = await ReadAsync(dst.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
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
                    await WasiInterop
                                .RegisterWasiPollable(output.Subscribe(), cancellationToken).ConfigureAwait(false);
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
