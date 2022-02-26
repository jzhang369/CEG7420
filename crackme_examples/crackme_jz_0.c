#include <stdio.h>
#include <string.h>
void main()
{
	char password[20];
	printf("Please enter your password:\n");
	scanf("%s", password);

	if(strcmp(password, "WrightCEG7420"))
	{
		printf("Correct Password!\n");
	}
	else
	{
		printf("Incorrect Password!\n");
	}

}
