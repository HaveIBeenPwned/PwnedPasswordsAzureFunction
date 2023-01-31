// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;

namespace HaveIBeenPwned.PwnedPasswords
{
    public struct HashEntry : IDisposable
    {
        private static ConcurrentStack<StringBuilder> s_stringbuilders = new ConcurrentStack<StringBuilder>();
        private static object s_lock = new object();
        private Memory<byte> _data = Memory<byte>.Empty;

        public ReadOnlyMemory<byte> Hash => _data.Slice(0, _data.Length - 4);
        public int Prevalence
        {
            get => BinaryPrimitives.ReadInt32BigEndian(_data.Slice(_data.Length - 4).Span);
            set => BinaryPrimitives.WriteInt32BigEndian(_data.Slice(_data.Length - 4).Span, value);
        }

        public HashEntry(ReadOnlySpan<byte> data, int prevalence)
        {
            _data = ArrayPool<byte>.Shared.Rent(data.Length + 4).AsMemory(0, data.Length + 4);
            data.CopyTo(_data.Span);
            Prevalence = prevalence;
        }

        public static bool TryParseFromText(ReadOnlySpan<char> prefix, ReadOnlySequence<byte> rest, out HashEntry entry)
        {
            int hashtextLength = (int)rest.Length;
            Span<byte> bytes = stackalloc byte[hashtextLength];
            rest.CopyTo(bytes);
            Span<char> chars = stackalloc char[prefix.Length + bytes.Length];
            prefix.CopyTo(chars);
            int numChars = Encoding.ASCII.GetChars(bytes, chars.Slice(prefix.Length));
            return TryParseFromText(chars.Slice(0, prefix.Length + numChars), out entry);
        }

        public static bool TryParseFromText(ReadOnlySequence<byte> hashtext, out HashEntry entry)
        {
            int textLength = (int)hashtext.Length;
            Span<byte> bytes = stackalloc byte[textLength];
            hashtext.CopyTo(bytes);
            Span<char> chars = stackalloc char[textLength];
            int numChars = Encoding.ASCII.GetChars(bytes, chars);
            return TryParseFromText(chars.Slice(0, numChars), out entry);
        }

        public static bool TryParseFromText(ReadOnlySpan<char> hashtext, out HashEntry hashEntry)
        {
            hashEntry = default;
            if (hashtext.IsEmpty)
            {
                return false;
            }

            int colonIndex = hashtext.IndexOf(':');
            if (colonIndex < 2 || (colonIndex == hashtext.Length))
            {
                return false;
            }

            ReadOnlySpan<char> hex = hashtext.Slice(0, colonIndex);
            if (hex.Length % 2 == 1)
            {
                return false;
            }

            ReadOnlySpan<char> prevalenceString = hashtext.Slice(colonIndex + 1);
            if (!int.TryParse(prevalenceString, out int prevalence))
            {
                return false;
            }

            int hexLengthInBytes = hex.Length / 2;
            Span<byte> bytes = stackalloc byte[hexLengthInBytes];
            for (int i = 0; i < hexLengthInBytes; i++)
            {
                try
                {
                    bytes[i] = (byte)((hex[i * 2].ToByte() << 4) | hex[i * 2 + 1].ToByte());
                }
                catch (ArgumentException)
                {
                    return false;
                }
            }

            hashEntry = new HashEntry(bytes, prevalence);
            return true;
        }

        public static bool TryParseFromBinary(ReadOnlySpan<char> prefix, ReadOnlySequence<byte> rest, int hashSizeInBytes, out HashEntry entry)
        {
            if(hashSizeInBytes < 16 || prefix.Length != 5 || rest.Length != hashSizeInBytes + 2 || (rest.FirstSpan[0] & 0xF0) > 0)
            {
                // We only support hash size of 16 bytes (NTLM or more).
                // Prefix must be a 5 character hex string and should be the first two bytes of the hash and the upper nibble (4 bits) of the third byte.
                // The rest should be the last hashSizeInBytes - 2 bytes of the hash and an additional 4 bytes of prevalence (big endian int32),
                // where the first byte should be the lower nibble (4 bits) of the third byte of the hash.
                // Rest of the data should have the first nibble of the first byte all zeros.
                entry = default;
                return false;
            }

            Span<byte> bytes = stackalloc byte[hashSizeInBytes + 4];
            rest.CopyTo(bytes.Slice(2));
            bytes[0] = (byte)(prefix[0].ToByte() << 4 | prefix[1].ToByte());
            bytes[1] = (byte)(prefix[2].ToByte() << 4 | prefix[3].ToByte());
            bytes[2] = (byte)(prefix[4].ToByte() << 4 | (bytes[2] & 0x0F));
            entry = new HashEntry(bytes.Slice(0, hashSizeInBytes), BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(hashSizeInBytes)));
            return true;
        }

        public static bool TryParseFromBinary(ReadOnlySequence<byte> hashBytes, int hashSizeInBytes, out HashEntry entry)
        {
            if (hashSizeInBytes < 16 || hashBytes.Length != hashSizeInBytes + 4)
            {
                // We only support hash size of 16 bytes (NTLM or more).
                // Prefix must be a 5 character hex string and should be the first two bytes of the hash and the upper nibble (4 bits) of the third byte.
                // The rest should be the last hashSizeInBytes - 2 bytes of the hash and an additional 4 bytes of prevalence (big endian int32),
                // where the first byte should be the lower nibble (4 bits) of the third byte of the hash.
                // Rest of the data should have the first nibble of the first byte all zeros.
                entry = default;
                return false;
            }

            Span<byte> bytes = stackalloc byte[hashSizeInBytes + 4];
            hashBytes.CopyTo(bytes);
            entry = new HashEntry(bytes.Slice(0, hashSizeInBytes), BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(hashSizeInBytes)));
            return true;
        }

        public static async IAsyncEnumerable<HashEntry> ParseBinaryHashEntries(int hashSizeInBytes, PipeReader pipeReader)
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
                    if (TryParseFromBinary(buffer.Slice(0, hashSizeInBytes + 4), hashSizeInBytes, out HashEntry entry))
                    {
                        yield return entry;
                    }

                    buffer = buffer.Slice(hashSizeInBytes + 4);
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
                    if (TryParseFromBinary(prefix, buffer.Slice(0, hashSizeInBytes + 2), hashSizeInBytes, out HashEntry entry))
                    {
                        yield return entry;
                    }

                    buffer = buffer.Slice(hashSizeInBytes + 2);
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        public static async IAsyncEnumerable<HashEntry> ParseTextHashEntries(string prefix, int hashSizeInBytes, PipeReader pipeReader)
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
                while (TryReadLine(ref buffer, result.IsCompleted, out ReadOnlySequence<byte> line) && TryParseFromText(prefix, line, out HashEntry entry))
                {
                    yield return entry;
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }
        public static async IAsyncEnumerable<HashEntry> ParseTextHashEntries(int hashSizeInBytes, PipeReader pipeReader)
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
                while (TryReadLine(ref buffer, result.IsCompleted, out ReadOnlySequence<byte> line) && TryParseFromText(line, out HashEntry entry))
                {
                    yield return entry;
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        public void WriteAsBinaryTo<T>(T bufferWriter, bool omitPrefix) where T : IBufferWriter<byte>
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
            if (!s_stringbuilders.TryPop(out StringBuilder? stringBuilder))
            {
                stringBuilder = new StringBuilder();
            }


            if (omitPrefix)
            {
                Span<char> hashChars = stackalloc char[(Hash.Length - 2) * 2];
                Span<byte> omittedPrefixData = stackalloc byte[Hash.Length - 2];
                Hash.Span[2..].CopyTo(omittedPrefixData);
                omittedPrefixData[0] = (byte)(omittedPrefixData[0] & 0x0F);
                HashExtensions.ConvertToHex(omittedPrefixData, hashChars);
                stringBuilder.Append(hashChars[1..]);
            }
            else
            {
                Span<char> hashChars = stackalloc char[Hash.Length * 2];
                Hash.Span.ConvertToHex(hashChars);
                stringBuilder.Append(hashChars);
            }

            stringBuilder.Append(':');
            stringBuilder.Append(CultureInfo.InvariantCulture, $"{Prevalence}");
            Encoding.ASCII.GetBytes(stringBuilder.ToString(), bufferWriter);

            stringBuilder.Clear();
            s_stringbuilders.Push(stringBuilder);
        }

        public void Dispose()
        {
            if (MemoryMarshal.TryGetArray(_data, out ArraySegment<byte> segment) && segment.Array is not null)
            {
                ArrayPool<byte>.Shared.Return(segment.Array);
            }
        }

        private static bool TryReadLine(ref ReadOnlySequence<byte> buffer, bool isComplete, out ReadOnlySequence<byte> line)
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
    }
}
