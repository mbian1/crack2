#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char *tryWord(char *plaintext, char *hashFilename) {
    // Compute the hash of the plaintext
    char *computedHash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *srcFile = fopen(hashFilename, "r");
    if (!srcFile) {
        fprintf(stderr, "Can't open %s for reading\n", hashFilename);
        free(computedHash); // Free memory allocated for the hash
        exit(1);
    }

    char line[1000];

    // Loop through the hash file
    while (fgets(line, sizeof(line), srcFile) != NULL) {
        // Strip newline character if present
        line[strcspn(line, "\n")] = '\0';

        // Compare the computed hash to the current line
        if (strcmp(computedHash, line) == 0) {
            fclose(srcFile);
            return computedHash; // Match found, return the hash
        }
    }

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(srcFile);
    free(computedHash); // Free memory if no match is found
    return NULL; // Return NULL if no match

}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading
    FILE *dictFile = fopen(argv[2], "r");
    if (!dictFile) {
        fprintf(stderr, "Error: Could not open dictionary file %s\n", argv[2]);
        exit(1);
    }

    char word[256]; // To store each word from the dictionary
    int crackedCount = 0;

    // Iterate through each word in the dictionary
    while (fgets(word, sizeof(word), dictFile)) {

        char *nl = strchr(word, '\n');
        if(nl) *nl = '\0'; 

        // Pass the word and hash file to tryWord
        char *foundHash = tryWord(word, argv[1]);
        if (foundHash) {
            printf("%s %s\n", foundHash, word); // Print the hash and cracked word
            free(foundHash); // Free memory allocated for the found hash
            crackedCount++;
        }
    }

    // Display the number of hashes cracked
    printf("%d hashes cracked!\n", crackedCount);

    // Close the dictionary file
    fclose(dictFile);

    return 0;
}