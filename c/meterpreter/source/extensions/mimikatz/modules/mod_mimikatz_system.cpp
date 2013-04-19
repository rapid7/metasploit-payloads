/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_system.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_system::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(user,		L"user",		L"Affiche l\'utilisateur courant"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(computer,	L"computer",	L"Affiche le nom d\'ordinateur courant"));
	return monVector;
}

bool mod_mimikatz_system::user(vector<wstring> * arguments)
{
	wstring monUser;
	
	if(mod_system::getUserName(&monUser))
		wcout << L"Utilisateur : " << monUser << endl;
	else
		wcout << L"mod_system::getUserName : " << mod_system::getWinError();

	return true;
}

bool mod_mimikatz_system::computer(vector<wstring> * arguments)
{
	wstring monComputer;
	
	if(mod_system::getComputerName(&monComputer))
		wcout << L"Ordinateur : " << monComputer << endl;
	else
		wcout << L"mod_system::getComputerName : " << mod_system::getWinError();

	return true;
}

