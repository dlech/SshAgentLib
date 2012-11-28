using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using System.Collections.ObjectModel;

namespace dlech.SshAgentLib
{
  public interface ISshKey : IDisposable
  {
    /// <summary>
    /// The SSH protocol version
    /// </summary>
    SshVersion Version { get; }

    /// <summary>
    /// The public key algorithm
    /// </summary>
    PublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// returns true if key does not have private key parameters
    /// </summary>
    bool IsPublicOnly { get; }

    /// <summary>
    /// The bit size of the key
    /// </summary>
    int Size { get; }

    /// <summary>
    /// The MD5 has of the public key
    /// </summary>
    byte[] MD5Fingerprint { get; }

    /// <summary>
    /// Comment associated with key
    /// </summary>
    string Comment { get; set; }

    /// <summary>
    /// List of key constraints applied to this key
    /// </summary>
    ReadOnlyCollection<Agent.KeyConstraint> Constraints { get; }

    /// <summary>
    /// Gets a copy of the public key parameters
    /// </summary>
    /// <returns></returns>
    AsymmetricKeyParameter GetPublicKeyParameters();

    /// <summary>
    /// Gets a copy of the private key parameters
    /// </summary>
    /// <returns></returns>
    AsymmetricKeyParameter GetPrivateKeyParameters();

    /// <summary>
    /// Add constraint to key
    /// </summary>
    /// <param name="aConstraint"></param>
    void AddConstraint(Agent.KeyConstraint aConstraint);
  }
}
