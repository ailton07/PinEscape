// PinEscape.cpp : Defines the entry point for the console application.
//

#include<stdlib.h>
#include "stdio.h"


// Origem: https://msdn.microsoft.com/pt-br/library/s58ftw19.aspx
#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>
#define _CRT_SECURE_NO_WARNINGS
#define UNINITIALIZED 0xFFFFFFFF

#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h> //PROCESSENTRY
// #include "MemUpdateMapInformations.h" vs #include <MemUpdateMapInformations.h>
// http://stackoverflow.com/a/7790180
#include "MemUpdateMapInformations.h"

#include <string.h>

#include <stdint.h>

unsigned char* search(int startAddress, int endAddress);

unsigned char* search(int startAddress);

// De acordo com:
// https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf
// Signature can be certain code or data
#define padrao
// #define _escape

void test()
{
	// Padrao default
	#ifndef padrao
	__asm {
		nop
		nop
		push eax
		pop eax
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
	}
	#endif
	// Padrao 1
	#ifdef padrao
	__asm {
		 mov eax,0x12345678
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
	}
	#endif

	printf("\ntest() address: %x\n", &test);
	printf("\nExecutou instrucoes asm\n");
}

void escape() {
  printf("Escaped!\n");
  // system("pause");
  // exit(0);
}

int main(int argc, char** argv)
{
	unsigned char* primeiraOcorrenciaAddress = 0;
	unsigned char* segundaOcorrenciaAddress = 0;
	int (*ptTest)() = NULL;

	// printf("Start ? \n\n");
	// system("pause");

	test();

	ptTest = (int(*)())&test;

	// printf("Executou test(); Continuar ? \n");
	//system("pause");

	primeiraOcorrenciaAddress = search((int)ptTest);
	printf("Endereco primeira ocorrencia: %x\n", primeiraOcorrenciaAddress);
	// system("pause");

	std::vector<MEMPAGE> pageVector = GetPageVector();
    int pagecount = (int)pageVector.size();

	 for(int i = 0; i < pagecount -1; i++)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		
		DWORD endAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;

		segundaOcorrenciaAddress = search((int)(currentPage.mbi.BaseAddress), (int)endAddress);

		if (segundaOcorrenciaAddress != 0 ) 
		{
			printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
			// system("pause");
			break;
		}


	}
	 if (segundaOcorrenciaAddress == 0 ) 
	 {
		 printf("\nSegunda ocorrencia nao foi localizada\n");
	 }
	 else 
	 {
		 int (*pEscape)() = NULL;
		 pEscape = (int(*)())&escape;
		 printf("\nescape() address: %x\n", pEscape);
		 // system("pause");
		 // x86
		  // segundaOcorrenciaAddress--;

#ifdef _escape
		  segundaOcorrenciaAddress[0] = 0x57; // push %rdi
          segundaOcorrenciaAddress[1] = 0xeb; // jmp 9
          segundaOcorrenciaAddress[2] = 0x06;
          segundaOcorrenciaAddress[3] = 0x68; // push &escape
          segundaOcorrenciaAddress[4] = (uint64_t)pEscape & 0xFF;
          segundaOcorrenciaAddress[5] = ((uint64_t)pEscape >> 8) & 0xFF;
          segundaOcorrenciaAddress[6] = ((uint64_t)pEscape >> 16) & 0xFF;
          segundaOcorrenciaAddress[7] = ((uint64_t)pEscape >> 24) & 0xFF;
          segundaOcorrenciaAddress[8] = 0xC3; // ret
          segundaOcorrenciaAddress[9] = 0xe8; // call 3
          segundaOcorrenciaAddress[10] = 0xf5;
          segundaOcorrenciaAddress[11] = 0xff;
          segundaOcorrenciaAddress[12] = 0xff;
          segundaOcorrenciaAddress[13] = 0xff;
          segundaOcorrenciaAddress[14] = 0x5f; // pop %rdi
#endif

#ifndef _escape
          segundaOcorrenciaAddress[0] = 0x90;
          segundaOcorrenciaAddress[1] = 0x90;
          segundaOcorrenciaAddress[2] = 0x90;
          segundaOcorrenciaAddress[3] = 0x90; 
          segundaOcorrenciaAddress[4] = 0x90;
          segundaOcorrenciaAddress[5] = 0x90;
          segundaOcorrenciaAddress[6] = 0x90;
          segundaOcorrenciaAddress[7] = 0x90;
          segundaOcorrenciaAddress[8] = 0x90; 
          segundaOcorrenciaAddress[9] = 0x90; 
          segundaOcorrenciaAddress[10] = 0x90;
          segundaOcorrenciaAddress[11] = 0x90;
          segundaOcorrenciaAddress[12] = 0x90;
          segundaOcorrenciaAddress[13] = 0x90;
          segundaOcorrenciaAddress[14] = 0x90;
#endif
		 test();
	 }

	//system("pause");
	 printf("\n\nFim do Programa\n");
    return 0;
}


unsigned char* search(int startAddress, int endAddress)
{
	unsigned char* data;
	int sig_count = 0;
	int j = 0;

	int address = startAddress;
	data = (unsigned char*)address;
	// printf("0x%x\n",data);
	while(data < (unsigned char*)endAddress) {
		__try {		
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				if (data[0] == 0xB8 &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					sig_count++;
					return data;
					break;
				 }
			else {
				
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678B8, endAddress - startAddress);
				#endif
			
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return 0;
			continue;
		}
	// for 
	} 
	return 0;
}

unsigned char* search(int startAddress)
{
	unsigned char* data;
	int sig_count = 0;
	int j = 0;

	int address = startAddress;
	int endAddress = 0x80000000 ;

	data = (unsigned char*)address;

	while(data < (unsigned char*)endAddress) {
		__try {
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				if (data[0] == 0xB8 &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					sig_count++;
					return data;
				 }
			else {
			
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678B8, endAddress - startAddress);
				#endif
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			continue;
		}

	} // for
	return 0;
}