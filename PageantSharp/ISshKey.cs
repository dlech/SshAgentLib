using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;

namespace dlech.PageantSharp
{
  public interface ISshKey : IDisposable
  {
    /// <summary>
    /// The SSH protocol version
    /// </summary>
    SshVersion Version { get; set; }

    /// <summary>
    /// The public key algorithm
    /// </summary>
    PublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// The bit size of the key
    /// </summary>
    int Size { get; }

    /// <summary>
    /// Used to store public and private key pair
    /// </summary>
    AsymmetricCipherKeyPair CipherKeyPair { get; set; }

    /// <summary>
    /// The MD5 has of the public key
    /// </summary>
    byte[] Fingerprint { get; }

    /// <summary>
    /// Comment associated with key
    /// </summary>
    string Comment { get; set; }
  }
}
