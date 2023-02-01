using System;

FEAL4 gg = new FEAL4();

Console.WriteLine("Исходный текст:");
string text = "nataliya";
Console.WriteLine(text);


byte[] a = System.Text.Encoding.UTF8.GetBytes(text);


byte[] key = new byte[8];
int[] per = new int[8]//первичный ключ в двоичном виде
    { 10000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000};
    
    for(int j=0; j < 8; j++)
    {
        for (int k = 0; k < 8; k++)
        {
            key[j] += Convert.ToByte((per[j] % 10) * Math.Pow(2, k));//конвертация ключа
            per[j] = per[j] / 10;
        }
    }

byte[] kr1 = new byte[4];
byte[] kl1 =new byte[4];
for(int i=0; i < 4; i++)//деление ключа на правый и левый
{
    kl1[i] = key[i];
    kr1[i] = key[i+4];
}

byte[,] K = new byte[6, 4];

/*генерация раундовых ключей*/
byte[] help0 = new byte[4];
help0 = gg.keygen(kr1, kl1);
for (int i=0;i<4; i++)
{
    K[0,i]=help0[i];
}

byte[] help1 = new byte[4];
help1 = gg.keygen(kl1, gg.XOR(kr1,help0));
for (int i = 0; i < 4; i++)
{
    K[1, i] = help1[i];
}

byte[] help2 = new byte[4];
help2 = gg.keygen(gg.XOR(kr1, help0), gg.XOR(kl1, help1));
for (int i = 0; i < 4; i++)
{
    K[2, i] = help2[i];
}

byte[] help3 = new byte[4];
help3 = gg.keygen(gg.XOR(kl1, help1), gg.XOR(gg.XOR(kr1, help0), help2));
for (int i = 0; i < 4; i++)
{
    K[3, i] = help3[i];
}

byte[] help4 = new byte[4];
help4 = gg.keygen(gg.XOR(gg.XOR(kr1, help0), help2), gg.XOR(gg.XOR(kl1, help1), help3));
for (int i = 0; i < 4; i++)
{
    K[4, i] = help4[i];
}

byte[] help5 = new byte[4];
help5 = gg.keygen(gg.XOR(gg.XOR(kl1, help1), help3), gg.XOR(gg.XOR(gg.XOR(kr1, help0), help2), help4));
for (int i = 0; i < 4; i++)
{
    K[5, i] = help5[i];
}
/*------------------------------------*/

byte[][] b = {
    new byte[] { K[0, 0], K[0,1], K[0, 2], K[0, 3]},
    new byte[] { K[1, 0], K[1,1], K[1, 2], K[1, 3]},
    new byte[] { K[2, 0], K[2,1], K[2, 2], K[2, 3]},
    new byte[] { K[3, 0], K[3,1], K[3, 2], K[3, 3]},
    new byte[] { K[4, 0], K[4,1], K[4, 2], K[4, 3]},
    new byte[] { K[5, 0], K[5,1], K[5, 2], K[5, 3]}
};

byte[] resultation = gg.Encrypt(a, b);//вызов функции шифрования текста


var result = System.Text.Encoding.Default.GetString(resultation);
Console.WriteLine("Криптограмма:");
Console.WriteLine(result);

byte[] resultation1 = gg.Decrypt(resultation, b);//вызов функции дешифрования криптограммы

var result22 = System.Text.Encoding.Default.GetString(resultation1);
Console.WriteLine("Расшифрованный текст:");
Console.WriteLine(result22);


/* класс алгоритма шиврования FEAL*/
class FEAL4
{
    public byte[] keygen(byte[] kr1, byte[] kl1)//функция генерации одного раундового ключа
    {
        byte t1 = (byte)(kr1[0] ^ kr1[1]);
        byte t2 = (byte)(kr1[2] ^ kr1[3]);
        byte fk1 = G1(t1, (byte)(t2 ^ kl1[0]));
        byte fk2 = G0(t2, (byte)(fk1 ^ kl1[1]));
        byte fk0 = G0(kr1[0], (byte)(fk1 ^ kl1[2]));
        byte fk3 = G1(kr1[3], (byte)(fk2 ^ kl1[3]));
        byte[] kk = new byte[4];
        kk[0] = fk0;
        kk[1] = fk1;
        kk[2] = fk2;
        kk[3] = fk3;

        return kk;
    }
    public byte G0(byte a, byte b)//сдвиг S0
    {
        return (byte)((((a + b) % 256) << 2) | (((a + b) % 256) >> 6));
    }

    public byte G1(byte a, byte b)//сдвиг S1
    {
        return (byte)((((a + b + 1) % 256) << 2) | (((a + b + 1) % 256) >> 6));
    }

    public byte[] F(byte[] x) //функция F
    {
        byte[] y = new byte[4];
        y[1] = G1((byte)(x[0] ^ x[1]), (byte)(x[2] ^ x[3]));
        y[0] = G0(x[0], y[1]);
        y[2] = G0(y[1], (byte)(x[2] ^ x[3]));
        y[3] = G1(y[2], x[3]);
        return y;
    }

    private void AddKeyPart(byte[] P, byte[] K)//функция для реализации попарного исключающего ИЛИ
    {
        for (int i = 0; i < 4; i++)
        {
            P[i] = (byte)(P[i] ^ K[i]);
        }
    }

    public byte[] XOR(byte[] a, byte[] b)//функция XOR
    {
        byte[] c = new byte[a.Length];
        for (int i = 0; i < c.Length; i++)
        {
            c[i] = (byte)(a[i] ^ b[i]);
        }
        return c;
    }
    public byte[] Encrypt(byte[] P, byte[][] K)//функция шифрования
    {
        byte[] LeftPart = new byte[4];
        byte[] RightPart = new byte[4];
        Array.Copy(P, 0, LeftPart, 0, 4);
        Array.Copy(P, 4, RightPart, 0, 4);
        AddKeyPart(LeftPart, K[4]);
        AddKeyPart(RightPart, K[5]);
        byte[] Round2Left = XOR(LeftPart, RightPart);
        byte[] Round2Right = XOR(LeftPart, F(XOR(Round2Left, K[0])));
        /*Console.WriteLine("1 раунд");
        for (int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round2Left[i], 2) + "  ");
        }
        for(int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round2Right[i], 2)+ "  ");
        }
        Console.WriteLine();*/
        byte[] Round3Left = Round2Right;
        byte[] Round3Right = XOR(Round2Left, F(XOR(Round2Right, K[1])));
        /*Console.WriteLine("2 раунд");
        for (int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round3Left[i], 2) + "  ");
        }
        for (int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round3Right[i], 2) + "  ");
        }
        Console.WriteLine();*/
        byte[] Round4Left = Round3Right;
        byte[] Round4Right = XOR(Round3Left, F(XOR(Round3Right, K[2])));
        /*Console.WriteLine("3 раунд");

        for (int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round4Left[i], 2) + "  ");
        }
        for (int i = 0; i < 4; i++)
        {
            Console.Write(Convert.ToString(Round4Right[i], 2) + "  ");
        }
        Console.WriteLine();*/

        byte[] CipherTextLeft = XOR(Round4Left, F(XOR(Round4Right, K[3])));
        byte[] CipherTextRight = XOR(Round4Right, CipherTextLeft);
        byte[] CipherText = new byte[8];
        Array.Copy(CipherTextLeft, 0, CipherText, 0, 4);
        Array.Copy(CipherTextRight, 0, CipherText, 4, 4);
        /*Console.WriteLine("Криптограмма в двоичном виде:");
        for(int i =0;i<8; i++)
        {
            Console.Write(Convert.ToString(CipherText[i],2) + "  ");
        }
        Console.WriteLine();*/
        return CipherText;
    }

    public byte[] Decrypt(byte[] P, byte[][] K)//функция дешифрования
    {
        byte[] LeftPart = new byte[4];
        byte[] RightPart = new byte[4];
        Array.Copy(P, 0, LeftPart, 0, 4);
        Array.Copy(P, 4, RightPart, 0, 4);

        byte[] Round4Right = XOR(LeftPart, RightPart);
        byte[] Round4Left = XOR(LeftPart, F(XOR(Round4Right, K[3])));

        byte[] Round3Right = Round4Left;
        byte[] Round3Left = XOR(Round4Right, F(XOR(Round3Right, K[2])));

        byte[] Round2Right = Round3Left;
        byte[] Round2Left = XOR(Round3Right, F(XOR(Round2Right, K[1])));

        byte[] Round1Right = Round2Left;
        byte[] Round1Left = XOR(Round2Right, F(XOR(Round1Right, K[0])));

        byte[] TextLeft = Round1Left;
        byte[] TextRight = XOR(Round1Left, Round1Right);
        AddKeyPart(TextLeft, K[4]);
        AddKeyPart(TextRight, K[5]);
        byte[] Text = new byte[8];
        Array.Copy(TextLeft, 0, Text, 0, 4);
        Array.Copy(TextRight, 0, Text, 4, 4);
        /*Console.WriteLine("Расшифрованный текст в двоичном виде");
        for (int i = 0; i < 8; i++)
        {
            Console.Write(Convert.ToString(Text[i], 2) + "  ");
        }
        Console.WriteLine();*/
        return Text;
    }
}
/*-------------------------------------------*/