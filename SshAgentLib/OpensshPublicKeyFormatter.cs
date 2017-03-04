//
// OpensshPublicKeyFormatter.cs
//
// Copyright (c) 2017 David Lechner
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
using System.IO;
using System.Linq;

namespace dlech.SshAgentLib
{
  public sealed class OpensshPublicKeyFormatter : KeyFormatter
  {

    public override void Serialize(Stream stream, object obj)
    {
      throw new NotImplementedException();
    }

    public override object Deserialize(Stream stream)
    {
      if (stream == null) {
        throw new ArgumentNullException("stream");
      }
      using (var reader = new StreamReader(stream)) {
        var line = reader.ReadLine();
        line = line.Trim();
        var algoName = new string(line.TakeWhile(c => !char.IsWhiteSpace(c)).ToArray());
        line = line.Substring(algoName.Length).Trim();
        var data = new string(line.TakeWhile(c => !char.IsWhiteSpace(c)).ToArray());
        line = line.Substring(data.Length).Trim();
        var comment = line;

        PublicKeyAlgorithm algo;
        if (!TryParsePublicKeyAlgorithm(algoName, out algo)) {
          var message = string.Format("Unknown algorithm: {0}", algoName);
          throw new KeyFormatterException(message);
        }

        var parser = new BlobParser(Util.FromBase64(data));
        OpensshCertificate cert;
        var publicKeyParams = parser.ReadSsh2PublicKeyData(out cert);
        var key = new SshKey(SshVersion.SSH2, publicKeyParams, null, comment, cert);
        return key;
      }
    }

    static bool TryParsePublicKeyAlgorithm(string text, out PublicKeyAlgorithm algo)
    {
      switch (text) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          algo = PublicKeyAlgorithm.SSH_RSA;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_CERT_V1:
          algo = PublicKeyAlgorithm.SSH_RSA_CERT_V1;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          algo = PublicKeyAlgorithm.SSH_DSS;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_DSA_CERT_V1:
          algo = PublicKeyAlgorithm.SSH_DSS_CERT_V1;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP256;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_CERT_V1:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V1;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_CERT_V1:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V1;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP521;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_CERT_V1:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V1;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ED25519:
          algo = PublicKeyAlgorithm.ED25519;
          break;
        case PublicKeyAlgorithmExt.ALGORITHM_ED25519_CERT_V1:
          algo = PublicKeyAlgorithm.ED25519_CERT_V1;
          break;
        default:
          algo = default(PublicKeyAlgorithm);
          return false;
      }

      return true;
    }
  }
}
