#include <iostream>

void __attribute__((constructor)) cssmh_entry()
{
	system("zenity --info");
}

void __attribute__((destructor)) cssmh_exit()
{
	
}
