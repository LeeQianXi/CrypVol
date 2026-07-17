using System.Security.Cryptography;
using System.Text;

namespace CrypVol.Lib;

public static partial class Extension
{
    public static Func<string, string> Utf8Hash =
        (Func<string, byte[]>)Encoding.UTF8.GetBytes << SHA256.HashData << Convert.ToHexString;

    extension<TL, TR>(TL)
    {
        public static TR operator >> (TL x, Func<TL, TR> f)
        {
            return f(x);
        }
    }

    extension<TL, TM, TR>(Func<TL, TM>)
    {
        public static Func<TL, TR> operator <<(Func<TL, TM> l, Func<TM, TR> r)
        {
            return x => r(l(x));
        }
    }
}