#include <stdio.h>
void main()
{

	int num1;
	int num2;
	double result; 
	scanf("%d", &num1);
	scanf("%d", &num2);

	if(num1 > 1 && num1 < 4 && num2>1 && num2 < 4)
	{
		result = (num1 + num2) / (num1 - num2);
	}
	else
		result = num1 -  num2;

	printf("%d, %d -> %f\n", num1, num2, result);
}
