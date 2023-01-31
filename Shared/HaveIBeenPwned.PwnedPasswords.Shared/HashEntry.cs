// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;

namespace HaveIBeenPwned.PwnedPasswords
{
    public struct HashEntry : IDisposable, IComparable<HashEntry>, IComparable
    {
        private static Decoder s_decoder = Encoding.UTF8.GetDecoder();
        private static object s_lock = new object();
        private Memory<byte> _data = Memory<byte>.Empty;

        public ReadOnlyMemory<byte> Hash => _data.Slice(0, _data.Length - 4);
        public int Prevalence
        {
            get => BinaryPrimitives.ReadInt32BigEndian(_data.Slice(_data.Length - 4).Span);
            set => BinaryPrimitives.WriteInt32BigEndian(_data.Slice(_data.Length - 4).Span, value);
        }

        public HashEntry(ReadOnlyMemory<byte> data, int prevalence)
        {
            _data = ArrayPool<byte>.Shared.Rent(data.Length + 4).AsMemory(0, data.Length + 4);
            data.CopyTo(_data);
            Prevalence = prevalence;
        }

        public HashEntry(ReadOnlySpan<char> prefix, ReadOnlySpan<char> suffix)
        {
            int totalLength = prefix.Length + suffix.Length;
            Span<char> tempSpan = stackalloc char[128];
            prefix.CopyTo(tempSpan);
            suffix.CopyTo(tempSpan.Slice(prefix.Length));

            ParseHashEntry(tempSpan.Slice(0, totalLength));
        }

        public HashEntry(ReadOnlySpan<char> hashtext)
        {
            ParseHashEntry(hashtext);
        }

        public HashEntry(ReadOnlySequence<byte> hashtext, bool isBinary)
        {
            if (isBinary)
            {
                ParseBinaryEntry(hashtext);
            }
            else
            {
                int length = (int)hashtext.Length;
                Span<byte> bytes = stackalloc byte[1024];
                hashtext.CopyTo(bytes);
                var chars = ArrayPool<char>.Shared.Rent(1024);
                int numChars = 0;
                lock (s_lock)
                {
                    numChars = s_decoder.GetChars(bytes.Slice(0, length), chars, true);
                }
                try
                {
                    ParseHashEntry(chars.AsSpan(0, numChars));
                }
                finally
                {
                    ArrayPool<char>.Shared.Return(chars);
                }
            }
        }

        public HashEntry(string prefix, ReadOnlySequence<byte> hashtext, bool isBinary)
        {
            if (isBinary)
            {
                ParseBinaryEntry(prefix, hashtext);
            }
            else
            {
                int length = (int)hashtext.Length;
                Span<byte> bytes = stackalloc byte[1024];
                hashtext.CopyTo(bytes);
                var chars = ArrayPool<char>.Shared.Rent(1024);
                int numChars = 0;
                prefix.CopyTo(chars);
                lock (s_lock)
                {
                    numChars = s_decoder.GetChars(bytes.Slice(0, length), chars.AsSpan(3), true);
                }
                try
                {
                    ParseHashEntry(chars.AsSpan(0, numChars));
                }
                finally
                {
                    ArrayPool<char>.Shared.Return(chars);
                }
            }
        }

        private void ParseHashEntry(ReadOnlySpan<char> hashtext)
        {
            if (hashtext.IsEmpty)
            {
                throw new ArgumentException("Hash format is invalid. Hash should be of the form [hexstring]:[prevalence]. Example: 1234567890ABCDEF:123");
            }

            int colonIndex = hashtext.IndexOf(':');
            if (colonIndex < 2 || (colonIndex == hashtext.Length))
            {
                throw new ArgumentException("Hash format is invalid. Hash should be of the form [hexstring]:[prevalence]. Example: 1234567890ABCDEF:123");
            }

            ReadOnlySpan<char> hex = hashtext.Slice(0, colonIndex);
            if (hex.Length % 2 == 1)
            {
                throw new ArgumentException("Hash format is invalid. Hash should be of the form [hexstring]:[prevalence]. Example: 1234567890ABCDEF:123");
            }

            var prevalenceString = hashtext.Slice(colonIndex + 1);
            if (!int.TryParse(prevalenceString, out int prevalence))
            {
                throw new ArgumentException("Hash format is invalid. Hash should be of the form [hexstring]:[prevalence]. Example: 1234567890ABCDEF:123");
            }

            int hexLengthInBytes = hex.Length / 2;
            var bytes = ArrayPool<byte>.Shared.Rent(hexLengthInBytes + 4);
            for (int i = 0; i < hexLengthInBytes; i++)
            {
                try
                {
                    bytes[i] = (byte)((hex[i * 2].ToByte() << 4) | hex[i * 2 + 1].ToByte());
                }
                catch (ArgumentException)
                {
                    throw new ArgumentException("Hash format is invalid. Hash should be of the form [hexstring]:[prevalence]. Example: 1234567890ABCDEF:123");
                }
            }

            BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(hexLengthInBytes), prevalence);
            _data = new Memory<byte>(bytes, 0, hexLengthInBytes + 4);
        }

        public static async IAsyncEnumerable<HashEntry> ParseHashEntries(PipeReader pipeReader)
        {
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    result = await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (TryReadLine(ref buffer, result.IsCompleted, out ReadOnlySequence<byte> line))
                {
                    yield return new HashEntry(line, false);
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        public static async IAsyncEnumerable<HashEntry> ParseBinaryHashEntries(PipeReader pipeReader, int hashSizeInBytes)
        {
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    result = await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (buffer.Length >= hashSizeInBytes + 4)
                {
                    yield return new HashEntry(buffer.Slice(0, hashSizeInBytes + 4), true);
                    buffer = buffer.Slice(hashSizeInBytes + 4);
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        public static async IAsyncEnumerable<HashEntry> ParseHashEntries(string prefix, PipeReader pipeReader)
        {
            var decoder = Encoding.UTF8.GetDecoder();
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    result = await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (TryReadLine(ref buffer, result.IsCompleted, out ReadOnlySequence<byte> line))
                {
                    int length = (int)line.Length;
                    var bytes = ArrayPool<byte>.Shared.Rent(length);
                    line.CopyTo(bytes);
                    var chars = ArrayPool<char>.Shared.Rent(length);
                    int numChars = decoder.GetChars(bytes, 0, length, chars, 0);
                    try
                    {
                        yield return new HashEntry(prefix, chars.AsSpan(0, numChars));
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(bytes);
                        ArrayPool<char>.Shared.Return(chars);
                    }
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        public static async IAsyncEnumerable<HashEntry> ParseBinaryHashEntries(string prefix, int hashSizeInBytes, PipeReader pipeReader)
        {
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    result = await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (buffer.Length >= hashSizeInBytes + 2)
                {
                    yield return new HashEntry(prefix, buffer.Slice(0, hashSizeInBytes + 2), true);
                    buffer = buffer.Slice(hashSizeInBytes + 2);
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        internal static bool TryReadLine(ref ReadOnlySequence<byte> buffer, bool isComplete, out ReadOnlySequence<byte> line)
        {
            while (buffer.Length > 0)
            {
                SequencePosition? position = buffer.PositionOf((byte)'\n');
                if (position.HasValue)
                {
                    line = buffer.Slice(buffer.Start, position.Value);
                    buffer = buffer.Slice(line.Length + 1);
                    return true;
                }
                else if (isComplete)
                {
                    // The pipe is complete but we don't have a newline character, this input probably ends without a newline char.
                    line = buffer;
                    buffer = buffer.Slice(buffer.End, 0);
                    return true;
                }
                else
                {
                    break;
                }
            }

            line = default;
            return false;
        }

        private void ParseBinaryEntry(ReadOnlySequence<byte> bytes)
        {
            _data = ArrayPool<byte>.Shared.Rent((int)bytes.Length).AsMemory(0, (int)bytes.Length);
            bytes.CopyTo(_data.Span);
        }

        private void ParseBinaryEntry(string prefix, ReadOnlySequence<byte> bytes)
        {
            int minimumLength = (int)bytes.Length + 2;
            _data = ArrayPool<byte>.Shared.Rent(minimumLength).AsMemory(0, minimumLength);
            bytes.CopyTo(_data.Slice(2).Span);
            _data.Span[0] = (byte)(prefix[0].ToByte() << 4 | prefix[1].ToByte());
            _data.Span[1] = (byte)(prefix[2].ToByte() << 4 | prefix[3].ToByte());
            _data.Span[2] = (byte)(prefix[4].ToByte() << 4 | _data.Span[2]);
        }

        public void WriteTo<T>(T bufferWriter, bool omitPrefix) where T : IBufferWriter<byte>
        {
            if (omitPrefix)
            {
                int sizeHint = _data.Length - 2;
                Span<byte> slice = bufferWriter.GetSpan(sizeHint).Slice(0, sizeHint);
                _data.Span[2..].CopyTo(slice);
                slice[0] = (byte)(slice[0] & 0x0F);
                bufferWriter.Advance(sizeHint);
            }
            else
            {
                Span<byte> slice = bufferWriter.GetSpan(_data.Length);
                _data.Span.CopyTo(slice);
                bufferWriter.Advance(_data.Length);
            }
        }

        public void WriteTextTo<T>(T bufferWriter, bool omitPrefix) where T : IBufferWriter<byte>
        {
            if (omitPrefix)
            {
                Span<byte> omittedPrefixData = stackalloc byte[Hash.Length - 2];
                Hash.Span[2..].CopyTo(omittedPrefixData);
                omittedPrefixData[0] = (byte)(omittedPrefixData[0] & 0x0F);
                Encoding.UTF8.GetBytes($"{PwnedPasswords.Hash.ConvertToHex(omittedPrefixData)[1..]}:{Prevalence.ToString(CultureInfo.InvariantCulture)}", bufferWriter);
            }
            else
            {
                Encoding.UTF8.GetBytes($"{PwnedPasswords.Hash.ConvertToHex(Hash.Span)}:{Prevalence.ToString(CultureInfo.InvariantCulture)}", bufferWriter);
            }
        }

        public void Dispose()
        {
            if(MemoryMarshal.TryGetArray(_data, out ArraySegment<byte> segment) && segment.Array is not null)
            {
                ArrayPool<byte>.Shared.Return(segment.Array);
            }
        }

        public int CompareTo(HashEntry other) => Hash.Span.SequenceCompareTo(other.Hash.Span);
        public int CompareTo(object? obj) => obj is HashEntry entry ? CompareTo(entry) : 0;
    }
}
