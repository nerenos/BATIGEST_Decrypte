using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace BATIGEST_Decrypte
{
    public class clCryptage
    {

        string _ChaineCrypte;
        string _ChaineDecrypte;

        string Source;
        string Context = "F+EOU5KU2N6VlcQJFgIDKg==";

        Int32 Rad = 8;
        Int32 Puis = 4;

        public clCryptage(string chaineCrypte)
        {
            _ChaineCrypte = chaineCrypte;
            Source = GetLabel(chaineCrypte.Substring(0, Rad * Puis));

        }

        public string GetLabel(string ka)
        {
            StringBuilder builder1 = new StringBuilder(ka);
            builder1[Rad] = ka[13];
            builder1[13] = ka[Rad];
            return builder1.ToString();
        }

        public void Dest(AesCryptoServiceProvider aes)
        {
            aes.Key = Convert.FromBase64String(Source);
            aes.IV = Convert.FromBase64String(Context);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
        }

        public bool f_Decrypte()
        {
            _ChaineDecrypte = null;
            byte[] buffer = Convert.FromBase64String(_ChaineCrypte.Substring(Rad * Puis));
            using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
            {
                Dest(provider);
                using (ICryptoTransform transform = provider.CreateDecryptor(provider.Key, provider.IV))
                {
                    using (MemoryStream stream = new MemoryStream(buffer))
                    {
                        using (CryptoStream stream2 = new CryptoStream(stream, transform, CryptoStreamMode.Read))
                        {
                            using (StreamReader reader = new StreamReader(stream2))
                            {
                                _ChaineDecrypte = reader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            return true;
		}

        public string GetDecrypte()
        {
            return _ChaineDecrypte;
        }
    }
}
