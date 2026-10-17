/*
 * ============================================================================
 * Mini Intrusion Detection System (Mini-IDS)
 * ============================================================================
 * 
 * Description:
 *   A beginner-friendly, signature-based Intrusion Detection System written in C.
 *   It reads known attack patterns from "signatures.txt" and scans a web server
 *   log file ("logs.txt") using the naive string matching algorithm.
 *   When a pattern is found inside a log line, an alert is printed with:
 *     - Line number
 *     - Attack type (e.g., SQL_INJECTION, XSS, PATH_TRAVERSAL)
 *     - Matched pattern
 *
 * Designed for students: Simple, modular, and well-commented.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 1024      /* Maximum length of a single log/signature line */
#define MAX_SIGNATURES 100     /* Maximum number of signatures we can store     */
#define MAX_STR_LEN 256        /* Maximum length for attack types and patterns  */

/*
 * Structure to represent a single attack signature.
 * Example:
 *   attack_type = "SQL_INJECTION"
 *   pattern     = "' OR '1'='1"
 */
typedef struct {
    char attack_type[MAX_STR_LEN];
    char pattern[MAX_STR_LEN];
} Signature;

/*
 * Helper function: strip_newline
 * ------------------------------
 * Removes trailing newline characters ('\n' or '\r') from the end of a string.
 * This ensures clean matching and printing.
 */
void strip_newline(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/*
 * Naive String Matching Algorithm
 * -------------------------------
 * Checks if 'pattern' appears anywhere inside 'text'.
 *
 * How it works:
 * 1. Get length of text (n) and pattern (m).
 * 2. If pattern is longer than text, it cannot possibly match, so return 0.
 * 3. Slide the pattern over the text, testing every starting position 'i'
 *    from 0 up to (n - m).
 * 4. At each position 'i', compare characters one by one with pattern[j].
 * 5. If all 'm' characters match, return 1 (Match Found).
 * 6. If mismatch occurs, advance 'i' by 1 and try again.
 * 7. If the loop finishes without a full match, return 0 (No Match).
 *
 * Time Complexity: O(n * m) in the worst case.
 */
int naive_search(const char *text, const char *pattern) {
    int n = strlen(text);
    int m = strlen(pattern);

    /* If pattern is empty, nothing to search */
    if (m == 0) {
        return 0;
    }

    /* If pattern is longer than text, match is impossible */
    if (m > n) {
        return 0;
    }

    /* Slide pattern across text */
    for (int i = 0; i <= n - m; i++) {
        int j;

        /* Compare pattern characters with text characters */
        for (j = 0; j < m; j++) {
            if (text[i + j] != pattern[j]) {
                break; /* Character mismatch, stop checking this position */
            }
        }

        /* If j reached m, all characters matched */
        if (j == m) {
            return 1; /* Match found! */
        }
    }

    return 0; /* No match found in the entire text */
}

/*
 * Function: load_signatures
 * -------------------------
 * Reads attack signatures from a file formatted as "AttackType|pattern".
 * Stores them in the provided array of Signature structs.
 * Returns the number of signatures loaded.
 */
int load_signatures(const char *filename, Signature signatures[], int max_signatures) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open signature file '%s'\n", filename);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), file) != NULL && count < max_signatures) {
        strip_newline(line);

        /* Skip empty lines or comment lines starting with '#' */
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        /*
         * Find the '|' separator dividing AttackType and pattern.
         * Example line: "SQL_INJECTION|' OR '1'='1"
         */
        char *pipe_ptr = strchr(line, '|');
        if (pipe_ptr != NULL) {
            *pipe_ptr = '\0'; /* Split string: line is now AttackType */
            char *pattern_ptr = pipe_ptr + 1; /* pattern starts after '|' */

            strncpy(signatures[count].attack_type, line, MAX_STR_LEN - 1);
            signatures[count].attack_type[MAX_STR_LEN - 1] = '\0';

            strncpy(signatures[count].pattern, pattern_ptr, MAX_STR_LEN - 1);
            signatures[count].pattern[MAX_STR_LEN - 1] = '\0';

            count++;
        }
    }

    fclose(file);
    return count;
}

/*
 * Function: scan_logs
 * -------------------
 * Reads log lines one by one from "logs.txt".
 * For each line, it scans against every loaded signature.
 * Whenever naive_search() returns 1, an alert is printed.
 */
void scan_logs(const char *filename, Signature signatures[], int signature_count) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open log file '%s'\n", filename);
        return;
    }

    char line[MAX_LINE_LEN];
    int line_number = 0;
    int alert_count = 0;

    printf("======================================================================\n");
    printf("                  MINI-IDS INTRUSION DETECTION SCAN                   \n");
    printf("======================================================================\n");

    /* Read each log line from the file */
    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        strip_newline(line);

        /* Scan this log line against EVERY loaded signature */
        for (int i = 0; i < signature_count; i++) {
            if (naive_search(line, signatures[i].pattern)) {
                /* Print alert with line number, attack type, and matched pattern */
                printf("[ALERT] Line %2d | Type: %-15s | Matched: \"%s\"\n",
                       line_number,
                       signatures[i].attack_type,
                       signatures[i].pattern);
                alert_count++;
            }
        }
    }

    fclose(file);

    /* Print scan summary */
    printf("======================================================================\n");
    printf("Scan Complete!\n");
    printf("  Total lines scanned : %d\n", line_number);
    printf("  Signatures checked  : %d\n", signature_count);
    printf("  Alerts triggered    : %d\n", alert_count);
    printf("======================================================================\n");
}

int main(void) {
    const char *sig_file = "signatures.txt";
    const char *log_file = "logs.txt";

    Signature signatures[MAX_SIGNATURES];

    /* Step 1: Load signatures from signatures.txt */
    int sig_count = load_signatures(sig_file, signatures, MAX_SIGNATURES);
    if (sig_count < 0) {
        return 1; /* Failed to open signatures file */
    }

    printf("Successfully loaded %d attack signatures from '%s'.\n\n", sig_count, sig_file);

    /* Step 2: Scan web server logs against the signatures */
    scan_logs(log_file, signatures, sig_count);

    return 0;
}
