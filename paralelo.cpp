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
#include <mpi.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string>

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
using std::ofstream;
using std::string;


string decrye(CBC_Mode<DES>::Decryption decryptor, string cipher_text, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE])
{
  string decipher_text;
  decryptor.SetKeyWithIV(key, 8, iv);
  StringSource s(cipher_text, true, new StreamTransformationFilter(decryptor, new StringSink(decipher_text), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING));
  return decipher_text;
}

bool validacion(CBC_Mode<DES>::Decryption decryptor, string cipher_text, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE], string kw)
{
  string text = decrye(decryptor, cipher_text, key, iv); 	
  if(text.find(kw) != std::string::npos){
    cout << endl << "Mensaje: " << text << endl;
    return true;
  }
  return false;
}

int main(int argc, char* argv[]) {
  int N, id;
  MPI_Status st;
  MPI_Request req;
  MPI_Comm comm = MPI_COMM_WORLD;
  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);
  

  if(argc < 2) {
    if(id == 0) cout << "error" << endl;
    exit(1);
  }
  
  string filename = argv[1];
  string keyW  = argv[2];
  string mode     = argv[3]; 
  
  if (id == 0) cout << "Nombre: " << filename << endl;
  if (id == 0) cout << "key: " << keyW << endl << endl;

  string read_line;
 
  ifstream file (filename);
  string plain;
 
  if (file.is_open())
  {
    while (getline(file, read_line))
    {
      plain = read_line;
    }
    file.close();
  }
  else
  {
    cout << "error";
  } 

  string cipher_text, encoded_text;

  AutoSeededRandomPool prng;
  
  SecByteBlock key(8);

  CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
 

  if(mode == "2")
  {
    cipher_text.clear();
    StringSource(plain, true,
      new HexDecoder(
        new StringSink(cipher_text)
      ) 
    );
  }
  
  else
  {
    CryptoPP::byte local_key[DES::KEYLENGTH] = {255, 0, 0, 0, 0, 0, 0, 0};
    
    encoded_text.clear();
    StringSource(local_key, 8, true,
      new HexEncoder(
        new StringSink(encoded_text)
      )
    );
  
    try
    {
      CBC_Mode< DES >::Encryption encryptor;
      encryptor.SetKeyWithIV(local_key, 8, iv);
  		
      StringSource(plain, true, 
        new StreamTransformationFilter(encryptor,
          new StringSink(cipher_text)
        )     
      ); 
    }

    catch(const CryptoPP::Exception& e)
    {
      cerr << e.what() << endl;
      exit(1);
    }

    encoded_text.clear();
    StringSource(cipher_text, true,
      new HexEncoder(
        new StringSink(encoded_text)
      ) 
    );
    ofstream ofile ("archivoSalida.txt");
    ofile << encoded_text;
    ofile.close();
  }
  try
  { 
    int flag;      
    long found = 0;

    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
   
    double start_time, end_time;
    start_time = MPI_Wtime();

    CBC_Mode< DES >::Decryption decryptor;
   
    unsigned char potential_key[8];

    bool encontraLlave = false;
   
    uint64_t next_i = id;

    while (!encontraLlave)
    {
      memcpy(potential_key, &next_i, 8);
      
      encontraLlave = validacion(decryptor, cipher_text, potential_key, iv, keyW);

      if (encontraLlave) {
        found = 1;
        end_time = MPI_Wtime();
        
        cout << endl << "Tiempo paralelo: " << end_time - start_time << endl;
        
        for(int node=0; node < N; node++)
        {
          MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
        }
      }
      MPI_Test(&req, &flag, &st);
      
      if (found) break;
      
      next_i = next_i + N;
    }

    MPI_Finalize();
    return 0;
  }
  catch(const CryptoPP::Exception& e)
  {
    cerr << e.what() << endl;
    exit(1);
  }
  return 0;
}



