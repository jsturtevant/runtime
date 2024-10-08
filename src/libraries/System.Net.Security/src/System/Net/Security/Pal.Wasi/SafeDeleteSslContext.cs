// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using WasiTlsWorld;
using WasiTlsWorld.wit.imports.wasi.io.v0_2_0;
using WasiTlsWorld.wit.imports.wasi.sockets.v0_2_0;


namespace System.Net
{
    internal sealed class SafeDeleteSslContext : SafeDeleteContext
    {
        private ITls.FutureStreams? future;

        private WasiStream? tlsStream { get; set; }
        private ITls.ClientConnection clientConnection { get; }
        private ITls.ClientHandshake handshake;
        private WasiStream hostProxy;

        public ITls.ClientConnection ClientConnection { get { return this.clientConnection; } }

        public SafeDeleteSslContext(SslAuthenticationOptions authOptions)
            : base(IntPtr.Zero)
        {
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
            hostProxy = new WasiStream(componentRead, componentWrite);

            clientConnection = new ITls.ClientConnection(hostTlsRead, hostTlsWrite);
            handshake = clientConnection.Connect(authOptions.TargetHost);

            //TODO could configure all the various client options here such as alpn, etc.
        }

        internal SecurityStatusPal FinishHandShake(ref ProtocolToken token)
        {
            while (true)
            {
                if (this.future is null)
                {
                    future = ITls.ClientHandshake.Finish(handshake);
                }
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
                        return new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
                    }
                    else
                    {
                        return new SecurityStatusPal(
                            SecurityStatusPalErrorCode.InternalError, new Exception("TLS handshake failed"));
                    }
                }
                else
                {
                    var poll = this.future.Subscribe();
                    if (!poll.Ready()){
                        ReadPendingWrites(ref token);
                        return new SecurityStatusPal(SecurityStatusPalErrorCode.ContinueNeeded);
                    }
                }
            }

        }

        public override bool IsInvalid => clientConnection == null;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        internal void Write(ReadOnlySpan<byte> inputBuffer)
        {
            // send to the host
            this.hostProxy.Write(inputBuffer);

            // if (inputBuffer.Length == 160){
            //     Console.WriteLine("going to skip reading for now since this is a header");
            //     //this.dontread = true;
            // }

            // if (inputBuffer.Length == 74) {
            //     Console.WriteLine("ready to read again!");
            //     //this.dontread = false;
            // }
        }

        internal void SslWrite(ReadOnlySpan<byte> input){
            tlsStream!.Write(input);
        }

        internal int SslRead(Span<byte> buffer){
            var readAtleast = buffer.Length;
            if (buffer.Length >= 100) {
                readAtleast = buffer.Length-100;
            }
            return tlsStream!.ReadAtLeast(buffer, readAtleast, false);
        }

        private const int DefaultCopyBufferSize = 81920;
        internal void ReadPendingWrites(ref ProtocolToken token)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultCopyBufferSize);
            var bytesRead = hostProxy.Read(buffer);
            if (bytesRead == 0) {
                token.Size = 0;
                token.Payload = null;
                return;
            }

            token.SetPayload(new ReadOnlySpan<byte>(buffer, 0, bytesRead));
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

        public override int Read(byte[] bytes, int offset, int length)
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
                            var poll = input.Subscribe();
                            PollInterop.Poll(new List<IPoll.Pollable>() { poll });
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

        public override void Write(byte[] bytes, int offset, int length)
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
                    var poll = output.Subscribe();
                    PollInterop.Poll(new List<IPoll.Pollable>() { poll });
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

    }
}
