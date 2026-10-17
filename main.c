/*
 * ============================================================================
 * Mini Intrusion Detection System (Mini-IDS)
 * ============================================================================
 * 
 * Description:
 *   A beginner-friendly, signature-based Intrusion Detection System written in C.
 *   It reads known attack patterns from "signatures.txt" and scans a web server
 *   log file ("logs.txt") using one of three algorithms chosen at runtime:
 *     1. Naive String Matching
 *     2. Knuth-Morris-Pratt (KMP) with LPS table
 *     3. Rabin-Karp with Rolling Hash (tracks spurious hits / collisions)
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
#include <ctype.h>
#include <stdint.h>

#define MAX_LINE_LEN 1024      /* Maximum length of a single log/signature line */
#define MAX_SIGNATURES 100     /* Maximum number of signatures we can store     */
#define MAX_STR_LEN 256        /* Maximum length for attack types and patterns  */

/*
 * ============================================================================
 * Rabin-Karp 64-bit Rolling Hash Configuration:
 * ============================================================================
 * RK_BASE : Number of characters in the alphabet (256 ASCII characters).
 * RK_PRIME: Prime modulus used for the 64-bit rolling hash.
 *
 * YOU CAN CHANGE RK_PRIME HERE TO COMPARE SPURIOUS HIT COUNTS:
 *   - 101LL        : Small prime (educational). Shows visible hash collisions
 *                    (~232 spurious hits on logs.txt).
 *   - 1000000007LL : Large prime (production-grade). Drastically minimizes
 *                    hash collisions (0 spurious hits on logs.txt).
 * ============================================================================
 */
#define RK_BASE 256LL
#define RK_PRIME 1000000007LL  /* <-- Change between 101LL and 1000000007LL */

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
 * ============================================================================
 * Function: compute_lps
 * ============================================================================
 *
 * Builds the LPS (Longest Prefix Suffix) table for the KMP algorithm.
 *
 * ----------------------------------------------------------------------------
 * STUDENT EXPLANATION GUIDE (How to explain this to a teacher or interviewer):
 * ----------------------------------------------------------------------------
 * 1. What does "LPS" stand for?
 *    LPS = "Longest Proper Prefix which is also a Suffix".
 *
 * 2. What do "Prefix", "Proper Prefix", and "Suffix" mean?
 *    Let's take the string "CAT":
 *    - Prefixes:        "", "C", "CA", "CAT"
 *    - Proper Prefixes: Prefixes that are NOT the whole string -> "", "C", "CA"
 *    - Suffixes:        "", "T", "AT", "CAT"
 *    - Proper Suffixes: Suffixes that are NOT the whole string -> "", "T", "AT"
 *
 * 3. What does lps[i] mean?
 *    For the substring pattern[0...i]:
 *    lps[i] is the length of the longest proper prefix that is identical
 *    to a suffix of pattern[0...i].
 *
 * 4. Why do we build this table?
 *    In the Naive search, whenever characters mismatch, we slide the pattern
 *    forward by only 1 character and re-check from scratch (wasting time).
 *    In KMP, when a mismatch occurs after matching several characters, the
 *    LPS table tells us:
 *    "You already know the characters up to this point! Look at lps[j-1] to see
 *    how many characters you can safely KEEP matched without starting over."
 *    Because of this, the text pointer 'i' NEVER moves backwards!
 *
 * 5. Step-by-Step Logic of building the table:
 *    - Rule 0: lps[0] is ALWAYS 0.
 *      Why? A 1-character string has no proper prefix/suffix (length would be 0).
 *
 *    - We use two pointers:
 *        'len' : Length of the previous longest matching prefix/suffix (starts at 0).
 *                It also points to the next character in the prefix we want to test!
 *        'i'   : The current character in the pattern we are calculating (starts at 1).
 *
 *    - While i < m (loop through pattern):
 *        * CASE 1: pattern[i] == pattern[len] (MATCH!)
 *          The matching prefix got 1 character longer!
 *          1. Increase len by 1 (len++)
 *          2. Store it: lps[i] = len
 *          3. Advance to the next character: i++
 *
 *        * CASE 2: pattern[i] != pattern[len] (MISMATCH!)
 *          The current prefix cannot be extended.
 *          - If len != 0:
 *            Can a shorter prefix still match?
 *            We fall back to the previous known match: len = lps[len - 1].
 *            CRITICAL NOTE: We do NOT advance 'i' yet! We stay on pattern[i]
 *            and check if this shorter prefix matches.
 *          - If len == 0:
 *            We backed up all the way to the start and found no match.
 *            1. lps[i] = 0
 *            2. Advance to the next character: i++
 *
 * 6. Quick Walkthrough Example: Pattern = "ABABC"
 *    - i = 0: 'A'       -> lps[0] = 0 (base case)
 *    - i = 1: 'B' != 'A' (len=0) -> lps[1] = 0, i++
 *    - i = 2: 'A' == 'A' (len=0) -> len becomes 1, lps[2] = 1 ("A" == "A"), i++
 *    - i = 3: 'B' == 'B' (len=1) -> len becomes 2, lps[3] = 2 ("AB" == "AB"), i++
 *    - i = 4: 'C' != 'A' (len=2) -> len drops to lps[2-1] = lps[1] = 0.
 *             Re-check 'C' != 'A' with len=0 -> lps[4] = 0, i++
 *    Final LPS Table: [0, 0, 1, 2, 0]
 *
 * Time Complexity:  O(m), where m is the length of pattern.
 * Space Complexity: O(m) to store the table.
 * ============================================================================
 */
void compute_lps(const char *pattern, int m, int lps[]) {
    int len = 0; /* Length of the previous longest prefix suffix */

    lps[0] = 0;  /* Base case: a single character has no proper prefix/suffix */

    int i = 1;
    while (i < m) {
        if (pattern[i] == pattern[len]) {
            /* Case 1: Match! The prefix extends by 1 character */
            len++;
            lps[i] = len;
            i++;
        } else {
            /* Case 2: Mismatch! */
            if (len != 0) {
                /*
                 * Fall back: check if a shorter prefix matches.
                 * NOTE: 'i' is NOT incremented here because we must re-evaluate
                 * pattern[i] against the shorter prefix.
                 */
                len = lps[len - 1];
            } else {
                /* No matching prefix suffix possible */
                lps[i] = 0;
                i++;
            }
        }
    }
}

/*
 * Knuth-Morris-Pratt (KMP) String Matching Algorithm
 * --------------------------------------------------
 * Searches for 'pattern' inside 'text' using the precomputed LPS table.
 *
 * How it works:
 * 1. Build the LPS table for 'pattern' using compute_lps().
 * 2. Maintain two indices:
 *      'i' -> walks through 'text' (never moves backwards!)
 *      'j' -> walks through 'pattern'
 * 3. While i < strlen(text):
 *      - If text[i] == pattern[j], advance both i and j.
 *      - If j reaches m (length of pattern), full match found! Return 1.
 *      - If text[i] != pattern[j] (mismatch):
 *          * If j != 0: skip redundant checks by setting j = lps[j - 1].
 *            (Notice 'i' remains in place; no text backtracking!)
 *          * If j == 0: advance text index i (i++).
 * 4. If end of text is reached without finding pattern, return 0.
 *
 * Time Complexity: O(n + m), where n = strlen(text), m = strlen(pattern).
 * Returns: 1 if pattern is found in text, 0 otherwise.
 */
int kmp_search(const char *text, const char *pattern) {
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

    /* Allocate memory for the LPS table */
    int *lps = (int *)malloc(m * sizeof(int));
    if (lps == NULL) {
        /* Fall back safely to naive search if memory allocation fails */
        return naive_search(text, pattern);
    }

    /* Step 1: Precompute the LPS table */
    compute_lps(pattern, m, lps);

    /* Step 2: Search pattern in text */
    int i = 0; /* Index for text */
    int j = 0; /* Index for pattern */
    int found = 0;

    while (i < n) {
        if (text[i] == pattern[j]) {
            i++;
            j++;
        }

        /* Full pattern matched */
        if (j == m) {
            found = 1;
            break; /* Pattern detected in this log line */
        } else if (i < n && text[i] != pattern[j]) {
            /* Mismatch after j matches */
            if (j != 0) {
                /* Use LPS table to avoid backtracking 'i' */
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }

    free(lps);
    return found;
}

/*
 * ============================================================================
 * Function: rabin_karp_search
 * ============================================================================
 *
 * Searches for 'pattern' inside 'text' using the Rabin-Karp algorithm.
 * Uses a rolling hash to check substrings in O(1) time per window shift.
 * Also tracks 'spurious hits' (hash collisions where the hash matches but
 * the actual characters do not).
 *
 * ----------------------------------------------------------------------------
 * STUDENT EXPLANATION GUIDE: THE ROLLING HASH
 * ----------------------------------------------------------------------------
 * 1. The Core Idea:
 *    Instead of comparing every character one by one (which is slow), we turn the
 *    pattern into a single number called a "hash". Then we calculate the hash of
 *    every window of text of the same length.
 *    - If the hashes don't match -> The strings definitely don't match!
 *    - If the hashes DO match    -> The strings MIGHT match, so we compare characters
 *                                  to confirm.
 *
 * 2. The 3-Digit Number Analogy (The easiest way to understand Rolling Hash!):
 *    Imagine you have the 3-digit number 456, and you want to slide over to 567:
 *      Step 1: Subtract the old leading digit (4):
 *              456 - (4 * 100) = 56
 *      Step 2: Shift remaining digits to the left (multiply by base 10):
 *              56 * 10 = 560
 *      Step 3: Add the new incoming digit (7):
 *              560 + 7 = 567!
 *
 *    That is EXACTLY what the rolling hash does in O(1) time!
 *    - Instead of base 10, we use base 256 (for all ASCII characters).
 *    - Instead of 100 (10^2), we use 'h' = (base^(m-1)) % prime.
 *    - We use '% prime' at every step to prevent integer overflow.
 *
 * 3. What is a "Spurious Hit" (False Positive)?
 *    Because we use '% prime' to keep numbers within integer bounds, two
 *    completely different strings might occasionally produce the SAME hash number!
 *    This is called a "hash collision".
 *    When a collision happens, our character-by-character check fails. That false
 *    alarm is counted as a "spurious hit".
 *
 * Time Complexity:
 *   - Best & Average Case: O(n + m)
 *   - Worst Case:          O(n * m) if many spurious hits occur.
 * ============================================================================
 */
int rabin_karp_search(const char *text, const char *pattern, int *spurious_hits) {
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

    /*
     * Use 64-bit integers (int64_t) for hash values.
     * This avoids integer overflow when using large primes like 1000000007.
     */
    int64_t p_hash = 0; /* 64-bit hash value for the pattern */
    int64_t t_hash = 0; /* 64-bit hash value for current window in text */
    int64_t h = 1;      /* Multiplier for leftmost character: (RK_BASE^(m-1)) % RK_PRIME */

    /*
     * Precompute h = pow(RK_BASE, m - 1) % RK_PRIME
     * This represents the "place value" of the leading character in our window.
     */
    for (int i = 0; i < m - 1; i++) {
        h = (h * RK_BASE) % RK_PRIME;
    }

    /*
     * Calculate initial 64-bit hash value for:
     * 1. The pattern
     * 2. The first window of text (text[0 ... m - 1])
     */
    for (int i = 0; i < m; i++) {
        p_hash = (RK_BASE * p_hash + (unsigned char)pattern[i]) % RK_PRIME;
        t_hash = (RK_BASE * t_hash + (unsigned char)text[i]) % RK_PRIME;
    }

    /* Slide the pattern window over the text one character at a time */
    for (int i = 0; i <= n - m; i++) {
        /*
         * Check if hash values match.
         * Only if the 64-bit hashes match do we do a full character-by-character check!
         */
        if (t_hash == p_hash) {
            int match = 1;

            /* Check characters one by one */
            for (int j = 0; j < m; j++) {
                if (text[i + j] != pattern[j]) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                return 1; /* Real match found! */
            } else {
                /*
                 * SPURIOUS HIT (Hash collision):
                 * Hashes matched, but actual strings did not!
                 * We record this false alarm and continue scanning.
                 */
                if (spurious_hits != NULL) {
                    (*spurious_hits)++;
                }
            }
        }

        /* Calculate hash value for the NEXT window (rolling hash update) */
        if (i < n - m) {
            /*
             * =================================================================
             * ROLLING HASH UPDATE (in simple words):
             * =================================================================
             * Slide the window 1 position to the right in O(1) constant time:
             *
             *   Step 1: Subtract old leftmost character falling out of the window:
             *           ((int64_t)text[i] * h)
             *
             *   Step 2: Shift remaining characters left by multiplying by base:
             *           * RK_BASE (256LL)
             *
             *   Step 3: Add new incoming character entering on the right:
             *           + text[i + m]
             *
             *   Step 4: Modulo by RK_PRIME to keep the number within 64-bit range.
             *
             * Using 64-bit arithmetic ensures that intermediate multiplication
             * does not overflow even with RK_PRIME = 1000000007LL.
             * =================================================================
             */
            t_hash = (RK_BASE * (t_hash - (int64_t)(unsigned char)text[i] * h) + (unsigned char)text[i + m]) % RK_PRIME;

            /*
             * In C, the '%' modulo operator on a negative number returns a
             * negative value. If t_hash became negative after subtraction,
             * adding RK_PRIME wraps it back into the positive range [0, RK_PRIME - 1].
             */
            if (t_hash < 0) {
                t_hash += RK_PRIME;
            }
        }
    }

    return 0; /* Pattern not found */
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
 * Algorithm Selection Enum
 * ------------------------
 * Represents the string matching algorithm chosen by the user.
 */
typedef enum {
    ALGO_NAIVE = 1,
    ALGO_KMP = 2,
    ALGO_RABIN_KARP = 3
} AlgorithmType;

/*
 * Helper function: string_equals_ignore_case
 * -----------------------------------------
 * Performs a case-insensitive string comparison.
 * Allows matching user input like "naive", "Naive", "kmp", "KMP", "rabin-karp".
 */
int string_equals_ignore_case(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
            return 0;
        }
        s1++;
        s2++;
    }
    return (*s1 == '\0' && *s2 == '\0');
}

/*
 * Function: choose_algorithm
 * --------------------------
 * Determines which string matching algorithm to use at runtime.
 *
 * It supports two convenient methods:
 * 1. Command-line argument:
 *      ./mini_ids naive        or   ./mini_ids 1
 *      ./mini_ids kmp          or   ./mini_ids 2
 *      ./mini_ids rabin-karp   or   ./mini_ids 3
 * 2. Interactive runtime menu:
 *      If no argument is given, it asks the user to choose.
 */
AlgorithmType choose_algorithm(int argc, char *argv[]) {
    /* Method 1: Check command-line argument if provided */
    if (argc >= 2) {
        if (strcmp(argv[1], "1") == 0 || string_equals_ignore_case(argv[1], "naive")) {
            return ALGO_NAIVE;
        }
        if (strcmp(argv[1], "2") == 0 || string_equals_ignore_case(argv[1], "kmp")) {
            return ALGO_KMP;
        }
        if (strcmp(argv[1], "3") == 0 ||
            string_equals_ignore_case(argv[1], "rabin-karp") ||
            string_equals_ignore_case(argv[1], "rabin-krap") ||
            string_equals_ignore_case(argv[1], "rabin") ||
            string_equals_ignore_case(argv[1], "karp") ||
            string_equals_ignore_case(argv[1], "rk")) {
            return ALGO_RABIN_KARP;
        }
        printf("Notice: Unrecognized argument '%s'. Please choose from the menu:\n\n", argv[1]);
    }

    /* Method 2: Interactive menu prompt */
    char input[64];
    while (1) {
        printf("----------------------------------------------------------------------\n");
        printf("Choose String Matching Algorithm:\n");
        printf("  [1] Naive String Matching Algorithm\n");
        printf("  [2] Knuth-Morris-Pratt (KMP) Algorithm with LPS Table\n");
        printf("  [3] Rabin-Karp Algorithm with Rolling Hash\n");
        printf("Enter your choice (1, 2, or 3): ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            /* Handled EOF (e.g., end of piped input) */
            printf("\nNo input received. Defaulting to Naive algorithm.\n");
            return ALGO_NAIVE;
        }

        strip_newline(input);

        if (strcmp(input, "1") == 0 || string_equals_ignore_case(input, "naive")) {
            return ALGO_NAIVE;
        } else if (strcmp(input, "2") == 0 || string_equals_ignore_case(input, "kmp")) {
            return ALGO_KMP;
        } else if (strcmp(input, "3") == 0 ||
                   string_equals_ignore_case(input, "rabin-karp") ||
                   string_equals_ignore_case(input, "rabin-krap") ||
                   string_equals_ignore_case(input, "rabin") ||
                   string_equals_ignore_case(input, "karp") ||
                   string_equals_ignore_case(input, "rk")) {
            return ALGO_RABIN_KARP;
        } else {
            printf("Invalid selection \"%s\". Please enter 1 (Naive), 2 (KMP), or 3 (Rabin-Karp).\n\n", input);
        }
    }
}

/*
 * Function: scan_logs
 * -------------------
 * Reads log lines one by one from "logs.txt".
 * For each line, it scans against every loaded signature using the
 * selected algorithm (Naive, KMP, or Rabin-Karp).
 * Whenever a match is found, an alert is printed.
 */
void scan_logs(const char *filename, Signature signatures[], int signature_count, AlgorithmType algo) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open log file '%s'\n", filename);
        return;
    }

    char line[MAX_LINE_LEN];
    int line_number = 0;
    int alert_count = 0;
    int spurious_hits = 0; /* Counts hash collisions for Rabin-Karp */

    const char *algo_name;
    if (algo == ALGO_KMP) {
        algo_name = "Knuth-Morris-Pratt (KMP)";
    } else if (algo == ALGO_RABIN_KARP) {
        algo_name = "Rabin-Karp (Rolling Hash)";
    } else {
        algo_name = "Naive String Matching";
    }

    printf("\n======================================================================\n");
    printf("                  MINI-IDS INTRUSION DETECTION SCAN                   \n");
    printf("======================================================================\n");
    if (algo == ALGO_RABIN_KARP) {
        printf("Selected Algorithm : %s (modulus q = %lld)\n", algo_name, (long long)RK_PRIME);
    } else {
        printf("Selected Algorithm : %s\n", algo_name);
    }
    printf("======================================================================\n");

    /* Read each log line from the file */
    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        strip_newline(line);

        /* Scan this log line against EVERY loaded signature */
        for (int i = 0; i < signature_count; i++) {
            int matched = 0;

            if (algo == ALGO_KMP) {
                matched = kmp_search(line, signatures[i].pattern);
            } else if (algo == ALGO_RABIN_KARP) {
                matched = rabin_karp_search(line, signatures[i].pattern, &spurious_hits);
            } else {
                matched = naive_search(line, signatures[i].pattern);
            }

            if (matched) {
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
    printf("  Algorithm used      : %s\n", (algo == ALGO_KMP) ? "KMP" : (algo == ALGO_RABIN_KARP) ? "Rabin-Karp" : "Naive");
    printf("  Total lines scanned : %d\n", line_number);
    printf("  Signatures checked  : %d\n", signature_count);
    printf("  Alerts triggered    : %d\n", alert_count);
    if (algo == ALGO_RABIN_KARP) {
        printf("  Hash modulus (q)    : %lld\n", (long long)RK_PRIME);
        printf("  Spurious hash hits  : %d (hash matches that turned out not to be real matches)\n", spurious_hits);
    }
    printf("======================================================================\n");
}

int main(int argc, char *argv[]) {
    const char *sig_file = "signatures.txt";
    const char *log_file = "logs.txt";

    Signature signatures[MAX_SIGNATURES];

    /* Step 1: Load signatures from signatures.txt */
    int sig_count = load_signatures(sig_file, signatures, MAX_SIGNATURES);
    if (sig_count < 0) {
        return 1; /* Failed to open signatures file */
    }

    printf("Successfully loaded %d attack signatures from '%s'.\n\n", sig_count, sig_file);

    /* Step 2: Choose algorithm at runtime (interactive prompt or CLI argument) */
    AlgorithmType algo = choose_algorithm(argc, argv);

    /* Step 3: Scan web server logs against the signatures using the chosen algorithm */
    scan_logs(log_file, signatures, sig_count, algo);

    return 0;
}
