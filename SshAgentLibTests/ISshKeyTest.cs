using System;
using System.Linq;
using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
    [TestFixture()]
    public class ISshKeyTest
    {
        [Test()]
        public void TestFormatSignature()
        {
            var random = new Random();
            var dsa_key = new SshKey(
                new DsaPublicKeyParameters(
                    new BigInteger(
                        "10783827985936883407800478884376885258012329124816552994400318669417122279843086645137200743427232531167766104260606805303022314906254403593803159583034340"
                    ),
                    new DsaParameters(
                        new BigInteger(
                            "13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223"
                        ),
                        new BigInteger("857393771208094202104259627990318636601332086981"),
                        new BigInteger(
                            "5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796"
                        )
                    )
                )
            );
            // test that dsa signature works when values are not full 20 bytes.
            var r_bytes = new byte[19];
            var s_bytes = new byte[19];
            random.NextBytes(r_bytes);
            random.NextBytes(s_bytes);
            var r = new DerInteger(r_bytes);
            var s = new DerInteger(s_bytes);
            var sequence = new DerSequence(r, s);
            var signature = dsa_key.FormatSignature(sequence.GetEncoded());
            Assert.That(signature.Count, Is.EqualTo(40));
        }
    }
}
