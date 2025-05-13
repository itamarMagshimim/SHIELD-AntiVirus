#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dirent.h"

#define SUCCESS 0
#define FAILURE 1


// STATUS: FINISHED
void error_handling()
{
    printf("An error occurred.\n");
    exit(FAILURE);
}

// STATUS: FINISHED
void startScanProcess()
{
    printf("Initiating scan...\n");
    printf("This operation may require several minutes to complete.\n");
}


// Purpose: give the client accessible UI for better experience.

// Parameters:
//   folderPath: displaying the folder path selected for scanning.
//   virusSignature: displaying the virus signature pattern to be used for detection.

// Return value:
//   Return the selected scan option:
//     1 - for quick scan.
//     2 - for advanced scan.

// Status: FINISHED
int welcome(char* folderPath, char* virusSignature)
{
    int choose = 0;

    do
    {
        printf("Welcome to 'SHIELD' anti virus\n\n");

        printf("Folder to scan: %s | ", folderPath);
        printf("Virus signature: %s\n", virusSignature);

        printf("Please choose:\n");
        printf("1. 'SHIELD' quick scan -  A fast scan for a quick overview of potential issues.\n");
        printf("2. 'SHIELD' advanced scan - A thorough scan for a detailed and comprehensive analysis.\n""");

        scanf("%d", &choose);
    }
    while (choose < 1 || choose > 2);

    return choose;
}


// Purpose: Appends a new line to the antiVirusLog.txt file with the given file name and scan condition ('clear' or 'injected').

// Parameters:
//   folderPath: Path to the directory containing antiVirusLog.txt.
//   fileName: The name of the file being logged.
//   condition: Scan result condition ('clear' or 'injected').

// Return values:
//   0 - success
//   1 - failure

// STATUS: FINISHED
int updateLog(char* folderPath, char* fileName, char* condition)
{
    char logFilePath[512];
    snprintf(logFilePath, sizeof(logFilePath), "%s\\antiVirusLog.txt", folderPath);

    FILE* file = fopen(logFilePath, "a");

    if (file == NULL)
    {
        error_handling();
    }

    fprintf(file, "%s - %s\r\n", fileName, condition);

    fclose(file);
    return SUCCESS;
}


// Purpose: Check if a specified word is present in a given file

// Parameters:
//   filePath: The path to the file to be checked
//   word: The word to search for in the file
//   condition:
//     1 - quick scan
//     2 - advanced scan

// Return value:
//   0 - The word is found in the file
//   1 - The word is not found in the file

// STATUS: ON WORK
int isWordInFile(char* filePath, char* word, int condition)
{
    FILE* file = fopen(filePath, "r");

    char line[1024];
    int totalLines = 0;


    if (file == NULL)
    {
        error_handling();
    }

    // Quick scan
    if (condition == 1)
    {
        while (fgets(line, sizeof(line), file))
        {
            totalLines++;
        }

        int edgeLines = totalLines / 5;

        rewind(file);
        int currentLine = 0;

        while (fgets(line, sizeof(line), file))
        {
            if (currentLine < edgeLines || currentLine > totalLines - edgeLines)
            {
                if (strstr(line, word) != NULL)
                {
                    fclose(file);
                    return SUCCESS;
                }
            }
            currentLine++;
        }
    }
    // Advanced scan
    if (condition == 2)
    {
        while (fgets(line, sizeof(line), file))
        {
            if (strstr(line, word) != NULL)
            {
                fclose(file);
                return SUCCESS;
            }
        }
    }

    fclose(file);
    return FAILURE;
}


// Purpose: Perform a virus scan on files in a directory using the specified scan mode.

// Parameters:
//   folderPath: Path to the directory to scan.
//   virusSignature: The virus signature to detect.
//   scanMode: 1 for quick scan (first & last 20%), 2 for advanced scan (full file).

// Return value:
//   0 - success.
//   1 - failure.

//STATUS: NEEDS TO BE CHECKED.
int scanFolder(char* folderPath, char* virusSignature, int scanMode)
{
    startScanProcess();

    DIR* dir = opendir(folderPath);
    struct dirent* entry;

    if (dir == NULL)
    {
        error_handling();
    }

    while ((entry = readdir(dir)))
    {
        char fullPath[1024];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", folderPath, entry->d_name);

        if (isWordInFile(fullPath, virusSignature, scanMode))
        {
            updateLog(folderPath, entry->d_name, "injected");
            printf("%s - %s\n", entry->d_name, "injected");
        }
        else
        {
            updateLog(folderPath, entry->d_name, "clear");
            printf("%s - %s\n", entry->d_name, "clear");
        }
    }

    closedir(dir);
    return SUCCESS;
}


// Purpose: print antiVirusLog.txt file.

// Parameters:
//   filePath: The full path to the file to be printed.

// Return value:
//   0 - success.
//   1 - failure.

// STATUS: FINISHED
int printFile(char* filePath)
{
    FILE* file = fopen(filePath, "r");
    int ch;

    if (file == NULL)
    {
        return FAILURE;
    }

    while ((ch =  fgetc(file)) != EOF)
    {
        putchar(ch);
    }
    fclose(file);

    return SUCCESS;
}


// Purpose: Manage the entire process of scanning a folder for checking virus signature.

// Parameters:
//   argc - (number of arguments passed to the program)
//   argv - (is a list of variables you type when you run your program)
//     argv[1] = folder to scan.
//     argv[2] = Virus Signature.

// Return value:
//   0 - success.
//   1 - failure.

// STATUS: FINISHED
int main(const int argc, char *argv[])
{
    if (argc < 3)
    {
        error_handling();
    }

    char* folderPath = argv[1];
    char* virusSignature = argv[2];
    char logFilePath[512];
    snprintf(logFilePath, sizeof(logFilePath), "%s\\antiVirusLog.txt", folderPath);

    int choose = welcome(folderPath, virusSignature);

    // Arrange the files in the folder in alphabetical order using the system call.
    char command[1024];
    snprintf(command, sizeof(command), "dir /b /o:n %s", folderPath);

    system(command);

    switch (choose)
    {
        case 1:
            if (scanFolder(folderPath, virusSignature, 1) != SUCCESS)
            {
                error_handling();
            }
            if (!printFile(logFilePath))
            {
                error_handling();
            }
            break;

        case 2:
            if (scanFolder(folderPath, virusSignature, 2) != SUCCESS)
            {
                error_handling();
            }
            if (!printFile(logFilePath))
            {
                error_handling();
            }
            break;

        default:
            error_handling();
    }

    printf("Scan completed.\n");
    printf("You can see log path result at: %s\n", logFilePath);

    return SUCCESS;
}


