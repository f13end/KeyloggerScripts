#include <windows.h> // For memcpy
#include "CryptoGear.h"


//  Constructor.
CCryptoGear::CCryptoGear(unsigned char* pKey, unsigned int lenKey, unsigned char ModeOfOperation, unsigned char InitializationVector)
{
	Initialize(pKey, lenKey, ModeOfOperation, InitializationVector);
}


//  Overloaded costructor with no arguments.
//  Must manually initialize keystream.
CCryptoGear::CCryptoGear()
{}


//  Cipher Initialization.
//  Generates keystream and set mode of operation.
void CCryptoGear::Initialize(unsigned char* pKey, unsigned int lenKey, unsigned char ModeOfOperation,unsigned char InitializationVector)
{
	m_ModeOfOperation = ModeOfOperation;

	unsigned int i;

	for (i = 0; i < m_lenKeystream; i++)
	{
		m_KeyStream[i] = i + InitializationVector;
	}

	for (i = 0; i < m_lenKeystream; i++)
	{
		// xor initial keystream element value(0 - 255) with corresponding byte from key offset
		m_KeyStream[i] ^= (lenKey + pKey[i % lenKey]) % 256;
	}
}


void CCryptoGear::Encrypt(unsigned char pData[], unsigned long lenData)
{
	unsigned long Offset;
	unsigned char KeyStream[m_lenKeystream];

	//Create a local copy of the original KeyStream.
	memcpy(KeyStream, m_KeyStream, m_lenKeystream * sizeof(unsigned char));

	// Calculate padding
	unsigned char extra = lenData % 4;
	// If plain-text data size is not a multiple of block size,
	// then we must add a temporary padding (will be removed after finishing encrypting)
	if (extra)
	{
		extra = 4 - extra;
		lenData += extra;
		pData = (unsigned char*)realloc(pData, lenData);
	}

	//Encrypt the data.
	for (Offset = 0; Offset < lenData; Offset = Offset + 4)
	{
		pData[Offset]                 ^= KeyStream[Offset % m_lenKeystream];
		pData[(Offset + 1) % lenData] += (pData[Offset]                 + KeyStream[ (Offset + 1) % m_lenKeystream]) % 256;
		pData[(Offset + 2) % lenData] += (pData[(Offset + 1) % lenData] - KeyStream[ (Offset + 2) % m_lenKeystream]) % 256;
		pData[(Offset + 3) % lenData] += (pData[(Offset + 2) % lenData] ^ KeyStream[ (Offset + 3) % m_lenKeystream]) % 256;

		if (m_ModeOfOperation == MODE_CBC)
		{
			if (Offset > 0)
			{
				// xor block with previous block.
				pData[Offset]                 ^= (pData[(Offset - 4) % lenData]) % 256;
				pData[(Offset + 1) % lenData] ^= (pData[(Offset - 3) % lenData]) % 256;
				pData[(Offset + 2) % lenData] ^= (pData[(Offset - 2) % lenData]) % 256;
				pData[(Offset + 3) % lenData] ^= (pData[(Offset - 1) % lenData]) % 256;
			}

			// keystream elements used in this block are shifted. 
			// This way on next key round the corresponding keystream byte will be different.
			for (unsigned char i = 0; i < 4; i++)
			{
				KeyStream[(Offset + i) % m_lenKeystream] += pData[(Offset + i) % lenData] % 256;
			}
		}
	}

	// Remove padding.
	if (extra)
	{
		lenData -= extra;
		pData = (unsigned char*)realloc(pData, lenData);
	}
}


void CCryptoGear::Decrypt(unsigned char pData[], unsigned long lenData)
{
	unsigned char KeyStream[m_lenKeystream];
	unsigned long Offset;
	unsigned char a, b, c, d;
	unsigned char e, f, g, h;
	unsigned char i, j, k;

	//Create a local copy of the original keystream.
	memcpy(KeyStream, m_KeyStream, m_lenKeystream * sizeof(unsigned char));

	// Calculate padding
	unsigned char extra = lenData % 4;
	// If data size is not a multiple of block size,
	// then we must temporarely add padding (will be removed after finishing decryption)
	if (extra)
	{
		extra = 4 - extra;
		lenData += extra;
		pData = (unsigned char*)realloc(pData, lenData);
	}

	//Decrypt the data.
	for (Offset = 0; Offset < lenData; Offset = Offset + 4)
	{
		if (m_ModeOfOperation == MODE_CBC)
		{
			// Save original encrypted bytes, used for key shifting later
			a = pData[Offset];
			b = pData[(Offset + 1) % lenData];
			c = pData[(Offset + 2) % lenData];
			d = pData[(Offset + 3) % lenData];

			// Do from second cycle
			if (Offset > 0)
			{
				// xor block with previous block
				pData[Offset] ^= e % 256;
				pData[(Offset + 1) % lenData] ^= f % 256;
				pData[(Offset + 2) % lenData] ^= g % 256;
				pData[(Offset + 3) % lenData] ^= h % 256;
			}

			// Store encrypted bytes of this block for next cycle
			e = a;
			f = b;
			g = c;
			h = d;
		}

		// Save xored bytes (or original encrypted bytes if we are using ECB). 
		// With those we can shift back keystream operations and obtain clear-text.
		i = pData[Offset];
		j = pData[(Offset + 1) % lenData];
		k = pData[(Offset + 2) % lenData];

		pData[Offset]                 ^= KeyStream[Offset % m_lenKeystream];
		pData[(Offset + 1) % lenData] -= (i	+ KeyStream[(Offset + 1) % m_lenKeystream]) % 256;
		pData[(Offset + 2) % lenData] -= (j - KeyStream[(Offset + 2) % m_lenKeystream]) % 256;
		pData[(Offset + 3) % lenData] -= (k ^ KeyStream[(Offset + 3) % m_lenKeystream]) % 256;

		if (m_ModeOfOperation == MODE_CBC)
		{
			// Values of KeyStream elements used in this block are modified. 
			// This way on each key round the corresponding key byte will be different.
			KeyStream[Offset % m_lenKeystream]		 += a;
			KeyStream[(Offset + 1) % m_lenKeystream] += b;
			KeyStream[(Offset + 2) % m_lenKeystream] += c;
			KeyStream[(Offset + 3) % m_lenKeystream] += d;
		}
	}

	// Remove padding.
	if (extra)
	{
		lenData -= extra;
		pData = (unsigned char*)realloc(pData, lenData);
	}
}
