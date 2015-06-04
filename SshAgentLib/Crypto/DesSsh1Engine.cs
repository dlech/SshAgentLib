//
// DesSsh1Engine.cs
//
// Author(s): Max Laverse
//
// Copyright (c) 2013 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace dlech.SshAgentLib.Crypto
{
  /*
   * SSH1 private keys are encrypted with non-standard version of 3DES
   * This specific engine was originally written in Java by
   * Pik Master (pikmaster@wp.pl) - 2005
   * <http://bouncy-castle.1462172.n4.nabble.com/Re-DESede-encryption-problem-td1462188.html>
   */

  public class DesSsh1Engine : IBlockCipher
  {
    #region Instance Variables

    private bool encrypting;
    private CbcBlockCipher desEngine1, desEngine2, desEngine3;

    #endregion

    #region Constants

    private const int BLOCK_SIZE = 8;

    #endregion

    #region Public Methods

    public void Init(bool encrypting, ICipherParameters parameters)
    {
      if (!(parameters is KeyParameter))
      {
        throw new ArgumentException("Invalid parameter passed to "+
          "DesSsh1Engine init - " + parameters.GetType());
      }

      this.encrypting = encrypting;

      byte[] passphraseKey = (parameters as KeyParameter).GetKey();
      if (passphraseKey.Length !=16)
      {
        throw new ArgumentException("key size different than 16 bytes");
      }

      byte[] keyPart1 = new byte[8];
      byte[] keyPart2 = new byte[8];

      Array.Copy(passphraseKey, keyPart1, 8);
      Array.Copy(passphraseKey, 8, keyPart2, 0, 8);

      desEngine1 = new CbcBlockCipher(new DesEngine());
      desEngine2 = new CbcBlockCipher(new DesEngine());
      desEngine3 = new CbcBlockCipher(new DesEngine());

      desEngine1.Init(encrypting, new KeyParameter(keyPart1));
      desEngine2.Init(!encrypting, new KeyParameter(keyPart2));
      desEngine3.Init(encrypting, new KeyParameter(keyPart1));
    }

    public int GetBlockSize()
    {
      return BLOCK_SIZE;
    }

    public int ProcessBlock(byte[] inBlock, int inOff, byte[] outBlock, int outOff)
    {
      if (encrypting)
      {
        desEngine1.ProcessBlock(inBlock, inOff, outBlock, outOff);
        desEngine2.ProcessBlock(outBlock, outOff, outBlock, outOff);
        desEngine3.ProcessBlock(outBlock, outOff, outBlock, outOff);
      }
      else
      {
        desEngine3.ProcessBlock(inBlock, inOff, outBlock, outOff);
        desEngine2.ProcessBlock(outBlock, outOff, outBlock, outOff);
        desEngine1.ProcessBlock(outBlock, outOff, outBlock, outOff);
      }
      return BLOCK_SIZE;
    }

    public void Reset()
    {
      desEngine1.Reset();
      desEngine2.Reset();
      desEngine3.Reset();
    }

    public string AlgorithmName     { get { return "DesSsh1Engine"; } }
    public bool IsPartialBlockOkay  { get { return false; } }

    #endregion

  }

}
