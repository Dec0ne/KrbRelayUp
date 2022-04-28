using Asn1;
using System.Security.Cryptography;

namespace KrbRelayUp
{
    public class KrbAlgorithmIdentifier
    {

        public Oid Algorithm { get; set; }
        public byte[] Parameters { get; set; }

        public KrbAlgorithmIdentifier(Oid algorithm, byte[] parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters;
        }

        public AsnElt Encode()
        {

            AsnElt parameters = AsnElt.Decode(Parameters);

            return AsnElt.Make(
                AsnElt.SEQUENCE, new[] {
                    AsnElt.MakeOID(Algorithm.Value),
                    parameters}
                );
        }
    }
}
