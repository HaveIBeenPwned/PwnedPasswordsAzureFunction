// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HaveIBeenPwned.PwnedPasswords;

public static class MD4
{
    private static uint RoundF(uint a, uint b, uint c, uint d, uint k, int s) => BitOperations.RotateLeft(a + ((b & c) | ((~b) & d)) + k, s);
    private static uint RoundG(uint a, uint b, uint c, uint d, uint k, int s) => BitOperations.RotateLeft(a + ((b & c) | (b & d) | (c & d)) + k + 0x5A827999, s);
    private static uint RoundH(uint a, uint b, uint c, uint d, uint k, int s) => BitOperations.RotateLeft(a + (b ^ c ^ d) + k + 0x6ED9EBA1, s);

    public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (destination.Length < 16)
        {
            throw new ArgumentException("destination required at least 16 bytes.", nameof(destination));
        }

        int paddedLenBit = source.Length / 64 * 64 + 56;
        if (paddedLenBit <= source.Length)
        {
            paddedLenBit += 64;
        }

        int requiredBytes = paddedLenBit + 8;
        using IMemoryOwner<byte> paddedMessageArray = MemoryPool<byte>.Shared.Rent(requiredBytes);
        Memory<byte> paddedMessage = paddedMessageArray.Memory[..requiredBytes];
        paddedMessage.Span.Clear();
        source.CopyTo(paddedMessage.Span);

        paddedMessage.Span[source.Length] = 0x80;
        Unsafe.WriteUnaligned(ref paddedMessage.Span[paddedLenBit], BitConverter.IsLittleEndian ? (ulong)(source.Length * 8) : BinaryPrimitives.ReverseEndianness((ulong)(source.Length * 8)));

        uint regA = 0x67452301;
        uint regB = 0xEFCDAB89;
        uint regC = 0x98BADCFE;
        uint regD = 0x10325476;

        Span<uint> processingBuffer = stackalloc uint[16];
        Span<uint> uints = MemoryMarshal.Cast<byte, uint>(paddedMessage.Span);

        // Note: ... "Process each 16-word block" ...
        for (int i = 0; i < paddedMessage.Length / 64; i++)
        {
            for (int j = 0; j < 16; j++)
            {
                int index = i * 16 + j;
                processingBuffer[j] = BitConverter.IsLittleEndian ? uints[index] : BinaryPrimitives.ReverseEndianness(uints[index]);
            }

            uint saveA = regA;
            uint saveB = regB;
            uint saveC = regC;
            uint saveD = regD;

            // Round 1
            for (int x = 0; x < 4; x++)
            {
                regA = RoundF(regA, regB, regC, regD, processingBuffer[x * 4], 3);
                regD = RoundF(regD, regA, regB, regC, processingBuffer[x * 4 + 1], 7);
                regC = RoundF(regC, regD, regA, regB, processingBuffer[x * 4 + 2], 11);
                regB = RoundF(regB, regC, regD, regA, processingBuffer[x * 4 + 3], 19);
            }

            // Round 2
            for (int x = 0; x < 4; x++)
            {
                regA = RoundG(regA, regB, regC, regD, processingBuffer[x], 3);
                regD = RoundG(regD, regA, regB, regC, processingBuffer[x + 4], 5);
                regC = RoundG(regC, regD, regA, regB, processingBuffer[x + 8], 9);
                regB = RoundG(regB, regC, regD, regA, processingBuffer[x + 12], 13);
            }

            // Round 3
            regA = RoundH(regA, regB, regC, regD, processingBuffer[0], 3);
            regD = RoundH(regD, regA, regB, regC, processingBuffer[8], 9);
            regC = RoundH(regC, regD, regA, regB, processingBuffer[4], 11);
            regB = RoundH(regB, regC, regD, regA, processingBuffer[12], 15);

            regA = RoundH(regA, regB, regC, regD, processingBuffer[2], 3);
            regD = RoundH(regD, regA, regB, regC, processingBuffer[10], 9);
            regC = RoundH(regC, regD, regA, regB, processingBuffer[6], 11);
            regB = RoundH(regB, regC, regD, regA, processingBuffer[14], 15);

            regA = RoundH(regA, regB, regC, regD, processingBuffer[1], 3);
            regD = RoundH(regD, regA, regB, regC, processingBuffer[9], 9);
            regC = RoundH(regC, regD, regA, regB, processingBuffer[5], 11);
            regB = RoundH(regB, regC, regD, regA, processingBuffer[13], 15);

            regA = RoundH(regA, regB, regC, regD, processingBuffer[3], 3);
            regD = RoundH(regD, regA, regB, regC, processingBuffer[11], 9);
            regC = RoundH(regC, regD, regA, regB, processingBuffer[7], 11);
            regB = RoundH(regB, regC, regD, regA, processingBuffer[15], 15);

            regA += saveA;
            regB += saveB;
            regC += saveC;
            regD += saveD;
        }

        Unsafe.WriteUnaligned(ref destination[0], BitConverter.IsLittleEndian ? regA : BinaryPrimitives.ReverseEndianness(regA));
        Unsafe.WriteUnaligned(ref destination[4], BitConverter.IsLittleEndian ? regB : BinaryPrimitives.ReverseEndianness(regB));
        Unsafe.WriteUnaligned(ref destination[8], BitConverter.IsLittleEndian ? regC : BinaryPrimitives.ReverseEndianness(regC));
        Unsafe.WriteUnaligned(ref destination[12], BitConverter.IsLittleEndian ? regD : BinaryPrimitives.ReverseEndianness(regD));
    }
}
