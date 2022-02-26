#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

bool check(char* pwd)
{
	int len = strlen(pwd);
	if(len <= 6)
		return false; 
	int sum = 0; 
	int temp = 0;
       	char a; 	
	for(int i = 0; i < len; i++)
	{
		a = pwd[i];
		sscanf(&a, "%d", &temp);  
		sum = sum + temp; 		
	}

	if(sum == 40)
		return true; 
	else
		return false; 

}	

bool check2(char* pwd)
{
	int len = strlen(pwd);
	if(len <= 6)
		return false; 

	if(pwd[0] == 'C' && pwd[1] == 'E' && pwd[2] == 'G')
		return true; 
	return false; 
}	


void main()
{
	char password[20];
	printf("Please enter your password:\n");
	scanf("%s", password);

	bool result1;
	bool result2; 
	result1 = check(password);
	result2 = check2(password);
	if(result1 && result2)
		printf("The password is correct!\n");
	else
		printf("The password is incorrect!\n");
}
