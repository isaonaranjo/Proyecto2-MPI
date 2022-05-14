/**************************************************************************
 Maria Isabel Ortiz Naranjo
 Luis Alejandro Urbina
 Proyecto 2
 Nos basamos en: https://github.com/weidai11/cryptopp
**************************************************************************/
#include "cryptopp/cryptlib.h"
#include "cryptopp/des.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <math.h>      
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
using namespace std::chrono;

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::DES;
using CryptoPP::Exception;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::SecByteBlock;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using std::cerr;
using std::cout;
using std::endl;
using std::exit;
using std::ifstream;
using std::string;


string decrye(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	string recovered;
	decryptor.SetKeyWithIV(key, 8, iv);
	StringSource s(cipher, true, 
		new StreamTransformationFilter(decryptor,
			new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING 
		)
	); 
	return recovered;
}

bool validacion(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	bool key_es = decrye(decryptor, cipher, key, iv).find("bubble") != std::string::npos;	
	return key_es;
}

int main(int argc, char* argv[]) {
	SecByteBlock key(8);
	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte key2[DES::KEYLENGTH] = {255, 255, 255, 255, 0, 0, 0, 0};
	AutoSeededRandomPool prng;
	string leer;
	string filename = "/home/isa/Documentos/Computacion Paralela/Proyecto2/archivo.txt";
	if (argv[1]!=NULL){
		filename = argv[1];
	}
	cout << "file" << filename << endl;
	ifstream file (filename);
	string text;
	if (file.is_open())
	{
		while ( getline (file,leer) )
		{
			text = leer;
		}
		file.close();
	}
	else
	{
		cout << "error" << endl;
		return 0;
	} 

	if(text.length() == 0){
		cout << "error";
		return 0;
	}
	else {
		string plain = text;
		string cipher, txexE, recovered;

		txexE.clear();
		StringSource(key2, 8, true,
			new HexEncoder(
				new StringSink(txexE)
			) 
		); 
		try
		{
			CBC_Mode< DES >::Encryption e;
			e.SetKeyWithIV(key2, 8, iv);
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				)       
			); 
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		txexE.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(txexE)
			) 
		); 
		try
		{
			int N, id;
	
			uint64_t upper = (uint64_t)(pow(2, 56)); 
			uint64_t _lower_limit, _upper_limit;
			auto initial_seq_time = high_resolution_clock::now();
			CBC_Mode< DES >::Decryption dd;

			unsigned char _byteArray[8];
			memcpy(_byteArray, &_lower_limit, 8);
			for (uint64_t i = _lower_limit; i < _upper_limit; i++)
			{
				memcpy(_byteArray, &i, 8);
				bool is_key = validacion(dd, cipher, _byteArray, iv);

				if (is_key) {
					break;
				}
			}
			auto final_seq_time = high_resolution_clock::now();
			auto seq_time = (final_seq_time - initial_seq_time);
			cout << "Tiempo secuencial: " << seq_time.count();
		
			return 0;
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		return 0;
	}
}


