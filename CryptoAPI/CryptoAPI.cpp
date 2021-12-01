// CryptoAPI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "framework.h"
#include "CryptoAPI.h"
#include <experimental/filesystem>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


#pragma comment(lib, "crypt32.lib")

CWinApp theApp;

class CryptoAPI
{
	HCRYPTPROV m_hCP = NULL;
	HCRYPTKEY m_hExchangeKey = NULL;
	HCRYPTKEY m_hSessionKey = NULL;
	HCRYPTKEY m_hExportKey = NULL;
public:

	HCRYPTKEY GetExchangeKey()
	{
		return m_hExchangeKey;
	}

	HCRYPTKEY GetSessionKey()
	{
		return m_hSessionKey;
	}

	HCRYPTKEY GetExportKey()
	{
		return m_hExportKey;
	}

	CryptoAPI()
	{
		if (!CryptAcquireContext(&m_hCP, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))	// ������������� ��������� ������, �� ������������� � ����������
			PrintError();
//		if (!CryptAcquireContext(&m_hCP, "My Container", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
//		{
//			if (GetLastError() == NTE_BAD_KEYSET)
//			{
//				if (!CryptAcquireContext(&m_hCP, "My Container", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
//					PrintError();
//			}
//		}
	}
	
	~CryptoAPI()
	{
		DestroyKeys();
		if (m_hCP)
		{
			if (!CryptReleaseContext(m_hCP, 0))
				PrintError();
		}
	}

	void GenKeyPair()
	{
		if (!CryptGenKey(m_hCP, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &m_hExchangeKey))
			PrintError();
	}

	void GenSessionKey()
	{
		if (!CryptGenKey(m_hCP, CALG_AES_256, CRYPT_EXPORTABLE, &m_hSessionKey))
			PrintError();
	}

	/// <summary>
	/// </summary>
	/// <param name="sPassword"></param>
	void GenExportKey(const string& sPassword)
	{
		HCRYPTHASH hHash;
		// �������� ������� ����
		if (!CryptCreateHash(m_hCP, CALG_SHA_256, NULL, 0, &hHash))
		{
			PrintError();
			return;
		}
		// ���������� ���� �������
		if(!CryptHashData(hHash, (BYTE*)sPassword.c_str(), sPassword.length(), 0))
		{
			PrintError();
			return;
		}
		
		/// ����� ���������� CryptGenKey �� ����������� ����, ��� ����� ����� ������������� �� ��������, � �������� �� ���
		// CALG_AES_256 - ����������� �������� ����������
		// CRYPT_EXPORTABLE - ����� ��� ����, ����� ����� �� ����� ��������� ���� � CryptExportKey
		if (!CryptDeriveKey(m_hCP, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &m_hExportKey))
			PrintError();

		CryptDestroyHash(hHash);	
	}

	void DestroyKey(HCRYPTKEY& hKey)
	{
		if (hKey)
		{
			if (!CryptDestroyKey(hKey))
				PrintError();
			hKey = NULL;
		}
	}

	void DestroyKeys()
	{
		DestroyKey(m_hExchangeKey);
		DestroyKey(m_hSessionKey);
		DestroyKey(m_hExportKey);
	}

	/// <summary>
	/// ������������ ���� �� ����������, ��������� ��������� � ����� ���������, ��� �������
	/// ������������ ���� � vector<v>, ������� ��������� ��� � ������ ��������� � ����� ������� � ����
	/// </summary>
	/// <param name="v">����, ������� ����� ������� � ����, � �������</param>
	/// <param name="hKey">
	///		��� ����, �� ���� ������� ������ � ��� ��, ��������� ��� ���� ������ CryptExportKey
	///		�� ����� hExpKey.
	///		���� ���������� � hKey: ExchangeKey - ��� ���� ����(public/private), �� ���� �� ����� ���������
	///		�� ���� dwType ( PRIVATEBLOB / PUBLICBLOB )
	///		���� ���������� � hKey: SessionKey - ��� ��� ���������� ����( �� - ������ �������) - ��������� ����� CryptDeriveKey
	///		�� �� ���������, ������ �� ��������� ����, ������� ������ � ������� ������ � ������������� ���������� AES_256
	///	</param>
	/// <param name="hExpKey">��� ����� ����������� ����</param>
	/// <param name="dwType">
	///		PUBLICBLOB  - ��������� ����
	///		PRIVATEBLOB - ��������� ����
	///		SIMPLEBLOB  - ���������� ����
	/// </param>
	void DoExportKey(vector<char>& v, HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwType)
	{
		DWORD dwLen = 0;
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, NULL, &dwLen))
		{
			PrintError();
			return;
		}
		v.resize(dwLen);
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, (BYTE*)v.data(), &dwLen))
			PrintError();
		v.resize(dwLen);		// ��������� ��� ��������� ������ �������� ������ ���������������� ������ 
								// ����� ���� ������ �������, ������������ ��� ��������
	}

	void DoImportKey(vector<char>& v, HCRYPTKEY& hKey, HCRYPTKEY hPubKey, DWORD dwType)
	{
		if (!CryptImportKey(m_hCP, (BYTE*)v.data(), v.size(), hPubKey, CRYPT_EXPORTABLE, &hKey))
			PrintError();
	}
	void ExportPublicKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}
	void ExportPrivateKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}
	void ExportSessionKey(vector<char>& v)
	{
		DoExportKey(v, m_hSessionKey, m_hExchangeKey, SIMPLEBLOB); // SIMPLEBLOB - ������ ����
	}

	void ImportPublicKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}

	void ImportPrivateKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}

	void ImportSessionKey(vector<char>& v)
	{
		DoImportKey(v, m_hSessionKey, NULL, SIMPLEBLOB);
	}

	void EncryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
		// CryptGetKeyParam � KP_BLOCKLEN ���������� ������ ����� � �����, 
		// ��� ����������� ���������� ����� ������������ ������� ��������,
		// �� RSA ������� ������� ������������ ����� ����� � ������,
		// ������ 11 ���� ����� ��� ������������� ����������� (padding)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			dwDataLen = dwRead;
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	void DecryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	// ������� vIn ������ - ������ hKey
	void EncryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			/// ��������� ���� hKey ������� ������ ������� (dwBlockLen ��� vIn.size() - dwDone)
			/// ������� ���� ���������� � vIn ������ � ���������� � ������ vOut ������������� ���� �� vIn

			// ���������� ������ ���������� �������� ��� ����������, ������ �� �������� ������ ����� 
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			// ������������ ����� vIn (�����, ������� �������) � ������ v
			memcpy(v.data(), vIn.data() + dwDone, dwRead); // dwRead - ������ �����
			// ����� ������ ����� ��� ������
			dwDone += dwRead;
			// ���� ������ ���� ����
			bDone = (dwDone == vIn.size());
			dwDataLen = dwRead; // ������������ ��� ����������� ����� 
			// ���������� ����� ����� ��� ����������
			// bDone - false, ������ � CryptEncrypt FINAL ���� ����� false
			// ������ ����� � ���� ������ ��� ����� ����������� ������ ��������� ������ �� dwDataLen
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			// ������� ����� ������� v
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			// ���������� ������������� ���� � ������, ������� � ������� ������,
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}

	void DecryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			memcpy(v.data(), vIn.data() + dwDone, dwRead);
			dwDone += dwRead;
			bDone = (dwDone == vIn.size());
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}
};

void CryptoTest()
{
	{
		CryptoAPI crypto;

		crypto.GenKeyPair(); // ���������/��������� ���� - ����
		crypto.GenSessionKey(); // ���������� ��������� SessionKey -- session
		crypto.GenExportKey("12345"); // ���������� ExportKey �� ������ ���� ���������������� �������
		{ // ���������� ��������� ���� ExchangeKey ����������� ExportKey ��������� ������ CryptExportKey
			vector<char> v;
			crypto.ExportPrivateKey(v);
			ofstream out("private.key", ios::binary);
			out.write(v.data(), v.size());
		}

		{ // ���������� ��������� ���� �� ExchangeKey, ������ ��� NULL � ���� ExportKey � ������ CryptExportKey
			vector<char> v;
			crypto.ExportPublicKey(v);
			ofstream out("public.key", ios::binary);
			out.write(v.data(), v.size());
		}

		// CryptExportKey �� �������, � ����������� ���������� �����, ������� ����� ������������ ��������� ����
		// ������� ���������� ���� �� ����� ExchangeKey(public/private)
		{
			vector<char> v;
			crypto.ExportSessionKey(v);
			ofstream out("session.key", ios::binary);
			out.write(v.data(), v.size());
		}


		{ // ������� ���������� ���� 
			vector<char> v1;
			vector<char> v2;
			crypto.ExportSessionKey(v1);
			crypto.EncryptData(v1, v2, crypto.GetExchangeKey(), true);
			ofstream out("session.enc.key", ios::binary);
			out.write(v2.data(), v2.size());
		}

		{ // ������ ���������� ����� � ������ �������������� ��������
			ifstream in("CryptoAPI.cpp", ios::binary);
			ofstream out("CryptoAPI.cpp.enc", ios::binary);
			crypto.EncryptData(in, out, (DWORD)experimental::filesystem::file_size("CryptoAPI.cpp"));
		}
	}

	
	{
		CryptoAPI crypto;

		crypto.GenExportKey("12345");
		{
			ifstream in("private.key", ios::binary);
			vector v(istreambuf_iterator<char>{in}, {});
			crypto.ImportPrivateKey(v);
		}

		{
			ifstream in("public.key", ios::binary);
			vector v(istreambuf_iterator<char>{in}, {});
			crypto.ImportPublicKey(v);
		}

		{
			ifstream in("session.key", ios::binary);
			vector v(istreambuf_iterator<char>{in}, {});
			crypto.ImportSessionKey(v);
		}

		{
			ifstream in("session.enc.key", ios::binary);
			vector v1(istreambuf_iterator<char>{in}, {});
			vector<char> v2;
			crypto.DecryptData(v1, v2, crypto.GetExchangeKey(), true);
			crypto.ImportSessionKey(v2);
		}

		{
			ifstream in("CryptoAPI.cpp.enc", ios::binary);
			ofstream out("CryptoAPI.cpp.dec", ios::binary);
			crypto.DecryptData(in, out, (DWORD)filesystem::file_size("CryptoAPI.cpp.enc"));
		}
	}
}

void print_menu(int& operation)
{
	cout << "0. Exit" << endl;
	cout << "1. Gen keys" << endl;
	cout << "2. Crypt" << endl;
	cout << "3. Decrypt" << endl;
	cout << "Choice: ";
	cin >> operation;
}

int main()
{     
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(nullptr);

	if (hModule != nullptr)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
		{
			// TODO: code your application's behavior here.
			wprintf(L"Fatal Error: MFC initialization failed\n");
			nRetCode = 1;
		}
		else
		{
			//CryptoAPI crypto;
			//while (true)
			//{
			//	int operation = 0;
			//	print_menu(operation);
			//	if (operation == 0) return 0;
			//	else if (operation == 1)
			//	{
			//		// ������� ��� �����
			//		crypto.GenKeyPair();
			//		crypto.GenSessionKey();
			//		string private_key_pass = "";
			//		cout << "Enter password for private key: ";
			//		cin >> private_key_pass;
			//		crypto.GenExportKey(private_key_pass);

			//		{ // ���������� ��������� ���� ExchangeKey ����������� ExportKey ��������� ������ CryptExportKey
			//			vector<char> v;
			//			crypto.ExportPrivateKey(v);
			//			ofstream out("private.key.txt", ios::binary);
			//			out.write(v.data(), v.size());
			//		}

			//		{ // ���������� ��������� ���� �� ExchangeKey, ������ ��� NULL � ���� ExportKey � ������ CryptExportKey
			//			vector<char> v;
			//			crypto.ExportPublicKey(v);
			//			ofstream out("public.key.txt", ios::binary);
			//			out.write(v.data(), v.size());
			//		}

			//		// CryptExportKey �� �������, � ����������� ���������� �����, ������� ����� ������������ ��������� ����
			//		// ������� ���������� ���� �� ����� ExportKey
			//		{
			//			vector<char> v;
			//			crypto.ExportSessionKey(v);
			//			ofstream out("session.key.txt", ios::binary);
			//			out.write(v.data(), v.size());
			//		}


			//		{ // ������� ���������� ���� (�� ������� ����� ����� ��� ExchangeKey)
			//			// ���� ���� ��� ExchangeKey, �� ���������� ���� ��������� ����� ��
			//			vector<char> v1;
			//			vector<char> v2;
			//			crypto.ExportSessionKey(v1);
			//			crypto.EncryptData(v1, v2, crypto.GetExchangeKey(), true);
			//			ofstream out("session.enc.key.txt", ios::binary);
			//			out.write(v2.data(), v2.size());
			//		}

			//	}
			//	else if (operation == 2)
			//	{
			//		string plaintext_filename;
			//		cout << "Enter filename to encrypt: "; 
			//		cin >> plaintext_filename;
			//		{ // ������ ���������� ����� � ������ �������������� ��������
			//			ifstream in(plaintext_filename, ios::binary);
			//			ofstream out(plaintext_filename + ".enc.txt", ios::binary);
			//			crypto.EncryptData(in, out, (DWORD)filesystem::file_size(plaintext_filename));
			//		}
			//	}
			//	else if (operation == 3)
			//	{
			//		// decrypt
			//	}
			//}
			CryptoTest();
		}
	}
	else
	{
		// TODO: change error code to suit your needs
		wprintf(L"Fatal Error: GetModuleHandle failed\n");
		nRetCode = 1;
	}

	return nRetCode;
}
