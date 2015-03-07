using System;
using System.Text;
using System.Security.Cryptography;

public interface IHasher
{
	#region Methods

	string Create (string text);

	bool Validate (string text, string security);

	#endregion
}

public class Hasher : IHasher
{
	#region Constructors

	public Hasher ()
	{
	}

	public Hasher (string algorithm, int iterations, int keySize, int saltSize)
	{
		Algorithm = algorithm;
		Iterations = iterations;
		KeySize = keySize;
		SaltSize = saltSize;
	}

	#endregion

	#region Implementation of IHasher

	public string Create (string text)
	{
		byte[] salt = GetSalt ();

		byte[] hash = GetHash (Algorithm, text, salt, Iterations, KeySize);

		return Algorithm + ":" + Iterations + ":" + KeySize + ":" + Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
	}

	public bool Validate (string text, string security)
	{
		char[] delimiter = { ':' };

		string[] segments = security.Split(delimiter);

		string algorithm = segments[SecuritySegment.Algorithm];
			
		int keySize = int.Parse(segments[SecuritySegment.KeySize]);
			
		int iterations = int.Parse(segments[SecuritySegment.Iterations]);
			
		byte[] salt = Convert.FromBase64String(segments[SecuritySegment.Salt]);
			
		byte[] hashStored = Convert.FromBase64String(segments[SecuritySegment.Hash]);

		byte[] hashComputed = GetHash(algorithm, text, salt, iterations, keySize);
			
		return ConstantTimeEquals (hashStored, hashComputed);
	}

	#endregion

	#region Private Methods

	private byte[] GetSalt ()
	{
		using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
		{
			byte[] salt = new byte[SaltSize];

			rng.GetBytes (salt);

			return salt;
		}
	}

	private byte[] GetHash (string algorithm, string text, byte[] salt, int iterations, int keySize)
	{
		byte[] textAsBytes = Encoding.UTF8.GetBytes(text);

		byte[] key = GetKey (textAsBytes, salt, iterations, keySize);

		KeyedHashAlgorithm hashAlgorithm = KeyedHashAlgorithm.Create(algorithm);

		hashAlgorithm.Key = key;

		byte[] saltedText = GetSaltedText (textAsBytes, salt);

		return hashAlgorithm.ComputeHash (saltedText);
	}

	private byte[] GetKey (byte[] text, byte[] salt, int iterations, int keySize)
	{
		using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(text, salt, iterations))
		{
			return pbkdf2.GetBytes(keySize);
		}
	}

	private byte[] GetSaltedText (byte[] text, byte[] salt)
	{
		byte[] saltedText = new byte[text.Length + salt.Length];

		for (int i = 0; i < text.Length; i++)
		{
			saltedText[i] = text[i];
		}

		for (int i = 0; i < salt.Length; i++)
		{
			saltedText[text.Length + i] = salt[i];
		}

		return saltedText;
	}

	private bool ConstantTimeEquals (byte[] a, byte[] b)
	{
		uint diff = (uint) a.Length ^ (uint) b.Length;

		for (int i = 0; (i < a.Length) && (i < b.Length); i++)
		{
			diff |= (uint) (a[i] ^ b[i]);
		}

		return diff == 0;
	}

	#endregion

	#region Public Properties

	public string Algorithm { get; set; }

	public int Iterations { get; set; }

	public int SaltSize { get; set; }

	public int KeySize { get; set; }

	#endregion

	#region Private Static Properties

	private static class SecuritySegment
	{
		public static readonly int Algorithm = 0;

		public static readonly int Iterations = 1;

		public static readonly int KeySize = 2;

		public static readonly int Salt = 3;

		public static readonly int Hash = 4;
	}

	#endregion
}
