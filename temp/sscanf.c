#include <stdio.h>

int main()
{
    char input[20];

    int year; 
    int day;
    char month[20];

    printf("Please enter a date (like - Feb 27 2022)\n");
    fgets(input, sizeof(input), stdin); 
    printf("your input is %s\n", input);

    sscanf(input, "%s %d %d", month, &day, &year); 
    printf("Year: %d\n", year); 
    printf("Month: %s\n", month); 
    printf("Day: %d\n", day); 

    //this is the patched code:
    /*
    int ret = sscanf(input, "%s %d %d", month, &day, &year); 
    if(ret == 3)
    {
        printf("ret saves the number of variables that are initialized.\n"); 
        printf("Now it is (partially) OK to proceed.\n");
        printf("Year: %d\n", year); 
        printf("Month: %s\n", month); 
        printf("Day: %d\n", day); 
    }
    else
    {
        printf("ERROR: the input does not have three elements.\n"); 
    }
    */



    return 0;  

}
