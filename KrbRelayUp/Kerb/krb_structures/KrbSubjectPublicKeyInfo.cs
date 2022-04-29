using Asn1;

namespace KrbRelayUp
{
    public class KrbSubjectPublicKeyInfo
    {

        public KrbAlgorithmIdentifier Algorithm { get; set; }
        public byte[] SubjectPublicKey { get; set; }

        public KrbSubjectPublicKeyInfo(KrbAlgorithmIdentifier algorithm, byte[] subjectPublicKey)
        {
            Algorithm = algorithm;
            SubjectPublicKey = subjectPublicKey;
        }

        public AsnElt Encode()
        {
            return AsnElt.Make(
                AsnElt.SEQUENCE, new[] {
                    Algorithm.Encode(),
                    AsnElt.MakeBitString(SubjectPublicKey)
            });

        }
    }
}
