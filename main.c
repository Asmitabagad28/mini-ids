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
#include <time.h>

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
 * Global comparison counter:
 * --------------------------
 * long long is used because the worst case can be huge
 * (e.g. 100 comparisons x 1,000,000 text characters = 100,000,000).
 *
 * It is incremented ONCE every time naive_search() or kmp_search()
 * compares one text character against one pattern character.
 * The caller resets it to 0 right before starting a search.
 */
long long comparisons = 0;

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
            comparisons++; /* Count this text-vs-pattern character comparison */
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
        comparisons = 0; /* Reset the counter before this search */
        return naive_search(text, pattern);
    }

    /* Step 1: Precompute the LPS table */
    compute_lps(pattern, m, lps);

    /* Step 2: Search pattern in text */
    int i = 0; /* Index for text */
    int j = 0; /* Index for pattern */
    int found = 0;

    while (i < n) {
        comparisons++; /* Count this text-vs-pattern character comparison */
        if (text[i] == pattern[j]) {
            i++;
            j++;
        }

        /* Full pattern matched */
        if (j == m) {
            found = 1;
            break; /* Pattern detected in this log line */
        } else if (i < n) {
            /*
             * Same check as before: text[i] != pattern[j].
             * It is only done when i < n, and we count it as another
             * character comparison because it really happens here.
             */
            comparisons++;
            if (text[i] != pattern[j]) {
                /* Mismatch after j matches */
                if (j != 0) {
                    /* Use LPS table to avoid backtracking 'i' */
                    j = lps[j - 1];
                } else {
                    i++;
                }
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
    ALGO_RABIN_KARP = 3,
    ALGO_BENCHMARK = 4,
    ALGO_WORST_CASE = 5
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
 * Determines which string matching algorithm or mode to use at runtime.
 *
 * It supports two convenient methods:
 * 1. Command-line argument:
 *      ./mini_ids naive        or   ./mini_ids 1
 *      ./mini_ids kmp          or   ./mini_ids 2
 *      ./mini_ids rabin-karp   or   ./mini_ids 3
 *      ./mini_ids benchmark    or   ./mini_ids 4
 *      ./mini_ids worstcase    or   ./mini_ids 5
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
        if (strcmp(argv[1], "4") == 0 ||
            string_equals_ignore_case(argv[1], "benchmark") ||
            string_equals_ignore_case(argv[1], "--benchmark") ||
            string_equals_ignore_case(argv[1], "-b") ||
            string_equals_ignore_case(argv[1], "bench")) {
            return ALGO_BENCHMARK;
        }
        if (strcmp(argv[1], "5") == 0 ||
            string_equals_ignore_case(argv[1], "worstcase") ||
            string_equals_ignore_case(argv[1], "worst-case") ||
            string_equals_ignore_case(argv[1], "--worstcase") ||
            string_equals_ignore_case(argv[1], "--worst-case") ||
            string_equals_ignore_case(argv[1], "worst") ||
            string_equals_ignore_case(argv[1], "wc")) {
            return ALGO_WORST_CASE;
        }
        printf("Notice: Unrecognized argument '%s'. Please choose from the menu:\n\n", argv[1]);
    }

    /* Method 2: Interactive menu prompt */
    char input[64];
    while (1) {
        printf("----------------------------------------------------------------------\n");
        printf("Choose String Matching Algorithm / Mode:\n");
        printf("  [1] Naive String Matching Algorithm\n");
        printf("  [2] Knuth-Morris-Pratt (KMP) Algorithm with LPS Table\n");
        printf("  [3] Rabin-Karp Algorithm with Rolling Hash\n");
        printf("  [4] Benchmark Mode (Log files 1K to 1M lines)\n");
        printf("  [5] Worst-Case Benchmark Mode (Text of repeating 'A's + pattern 'A...AB')\n");
        printf("Enter your choice (1, 2, 3, 4, or 5): ");
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
        } else if (strcmp(input, "4") == 0 ||
                   string_equals_ignore_case(input, "benchmark") ||
                   string_equals_ignore_case(input, "--benchmark") ||
                   string_equals_ignore_case(input, "-b") ||
                   string_equals_ignore_case(input, "bench")) {
            return ALGO_BENCHMARK;
        } else if (strcmp(input, "5") == 0 ||
                   string_equals_ignore_case(input, "worstcase") ||
                   string_equals_ignore_case(input, "worst-case") ||
                   string_equals_ignore_case(input, "--worstcase") ||
                   string_equals_ignore_case(input, "--worst-case") ||
                   string_equals_ignore_case(input, "worst") ||
                   string_equals_ignore_case(input, "wc")) {
            return ALGO_WORST_CASE;
        } else {
            printf("Invalid selection \"%s\". Please enter 1, 2, 3, 4, or 5.\n\n", input);
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
                comparisons = 0; /* Reset the counter before this search */
                matched = kmp_search(line, signatures[i].pattern);
            } else if (algo == ALGO_RABIN_KARP) {
                matched = rabin_karp_search(line, signatures[i].pattern, &spurious_hits);
            } else {
                comparisons = 0; /* Reset the counter before this search */
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

/*
 * Structure to store benchmark timing results for a specific log size.
 */
typedef struct {
    int lines;         /* Number of log lines tested */
    double naive_ms;   /* Time in milliseconds for Naive search */
    double kmp_ms;     /* Time in milliseconds for KMP search */
    double rk_ms;      /* Time in milliseconds for Rabin-Karp search */
} BenchmarkResult;

/*
 * Function: scan_benchmark
 * ------------------------
 * Scans a test log file against all loaded signatures using the specified algorithm,
 * WITHOUT printing alerts to stdout.
 *
 * Why we do not print alerts during benchmark:
 *   Printing thousands of alerts to the console would cause terminal I/O bottlenecks,
 *   obscuring the actual algorithmic performance differences we want to measure.
 *
 * Returns:
 *   Total count of alerts triggered (retained to prevent compiler dead code elimination).
 */
int scan_benchmark(const char *filename, Signature signatures[], int sig_count, AlgorithmType algo) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open test log file '%s'\n", filename);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int alert_count = 0;
    int spurious_hits = 0; /* Tracked for Rabin-Karp */

    /* Read each log line from the file */
    while (fgets(line, sizeof(line), file) != NULL) {
        strip_newline(line);

        /* Scan this line against every attack signature */
        for (int i = 0; i < sig_count; i++) {
            int matched = 0;

            if (algo == ALGO_NAIVE) {
                comparisons = 0; /* Reset the counter before this search */
                matched = naive_search(line, signatures[i].pattern);
            } else if (algo == ALGO_KMP) {
                comparisons = 0; /* Reset the counter before this search */
                matched = kmp_search(line, signatures[i].pattern);
            } else if (algo == ALGO_RABIN_KARP) {
                matched = rabin_karp_search(line, signatures[i].pattern, &spurious_hits);
            }

            if (matched) {
                alert_count++;
            }
        }
    }

    fclose(file);
    return alert_count;
}

/*
 * Function: create_test_log
 * -------------------------
 * Generates a test log file with 'target_lines' lines by repeating the
 * sample lines from the source log file in circular order.
 *
 * Parameters:
 *   filename     - Output file path (e.g., "test_logs_1000.txt")
 *   sample_lines - Array of strings containing the source log lines
 *   num_samples  - Number of lines in sample_lines
 *   target_lines - Desired number of lines to write (1000, 10000, etc.)
 *
 * Returns:
 *   1 on success, 0 on failure.
 */
int create_test_log(const char *filename, char *sample_lines[], int num_samples, int target_lines) {
    FILE *out = fopen(filename, "w");
    if (out == NULL) {
        printf("Error: Could not create test log file '%s'\n", filename);
        return 0;
    }

    /* Repeat sample lines until target_lines lines have been written */
    for (int i = 0; i < target_lines; i++) {
        fputs(sample_lines[i % num_samples], out);
    }

    fclose(out);
    return 1;
}

/*
 * Function: run_benchmark
 * -----------------------
 * Executes the performance benchmark across 1,000, 10,000, 100,000,
 * and 1,000,000 log lines.
 *
 * Workflow:
 *   1. Reads sample lines from "logs.text" (or "logs.txt").
 *   2. Generates test log files by repeating lines for each target size.
 *   3. Measures CPU time with clock() for Naive, KMP, and Rabin-Karp searches.
 *   4. Prints a formatted comparison table of milliseconds per algorithm.
 *   5. Saves the table to "result.csv".
 */
void run_benchmark(Signature signatures[], int sig_count) {
    /* Step 1: Open source log file (checks logs.text first, then logs.txt) */
    const char *src_filename = "logs.text";
    FILE *src_file = fopen("logs.text", "r");
    if (src_file == NULL) {
        src_file = fopen("logs.txt", "r");
        if (src_file != NULL) {
            src_filename = "logs.txt";
        }
    }

    if (src_file == NULL) {
        printf("Error: Could not open source log file ('logs.text' or 'logs.txt') to generate test logs.\n");
        return;
    }

    /* Load all sample lines into memory */
    #define MAX_SAMPLE_LINES 10000
    char *sample_lines[MAX_SAMPLE_LINES];
    int num_samples = 0;
    char buffer[MAX_LINE_LEN];

    while (fgets(buffer, sizeof(buffer), src_file) != NULL && num_samples < MAX_SAMPLE_LINES) {
        /* Ensure each line ends with a newline character */
        int len = strlen(buffer);
        if (len > 0 && buffer[len - 1] != '\n') {
            if (len < MAX_LINE_LEN - 1) {
                buffer[len] = '\n';
                buffer[len + 1] = '\0';
                len++;
            }
        }

        sample_lines[num_samples] = (char *)malloc(len + 1);
        if (sample_lines[num_samples] == NULL) {
            printf("Error: Memory allocation failed while loading sample log lines.\n");
            fclose(src_file);
            for (int j = 0; j < num_samples; j++) {
                free(sample_lines[j]);
            }
            return;
        }
        strcpy(sample_lines[num_samples], buffer);
        num_samples++;
    }
    fclose(src_file);

    if (num_samples == 0) {
        printf("Error: Source log file '%s' is empty.\n", src_filename);
        return;
    }

    printf("=========================================================================\n");
    printf("                  MINI-IDS PERFORMANCE BENCHMARK MODE                   \n");
    printf("=========================================================================\n");
    printf("Loaded %d sample lines from '%s'.\n", num_samples, src_filename);
    printf("Testing sizes: 1,000, 10,000, 100,000, and 1,000,000 lines.\n");
    printf("Timing Naive, KMP, and Rabin-Karp algorithms with clock()...\n");
    printf("=========================================================================\n\n");

    const int test_sizes[] = {1000, 10000, 100000, 1000000};
    const char *size_labels[] = {"1,000", "10,000", "100,000", "1,000,000"};
    int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    BenchmarkResult results[4];

    /* Step 2: Generate test files and benchmark each size */
    for (int s = 0; s < num_sizes; s++) {
        int target = test_sizes[s];
        results[s].lines = target;

        char filename[64];
        snprintf(filename, sizeof(filename), "test_logs_%d.txt", target);

        printf("[%d/%d] Creating test log file '%s' (%s lines)... ",
               s + 1, num_sizes, filename, size_labels[s]);
        fflush(stdout);

        if (!create_test_log(filename, sample_lines, num_samples, target)) {
            printf("Failed!\n");
            continue;
        }
        printf("Done.\n");

        /* Benchmark Naive Search */
        printf("      Running Naive search      ... ");
        fflush(stdout);
        clock_t start_naive = clock();
        scan_benchmark(filename, signatures, sig_count, ALGO_NAIVE);
        clock_t end_naive = clock();
        results[s].naive_ms = ((double)(end_naive - start_naive) * 1000.0) / CLOCKS_PER_SEC;
        printf("%.2f ms\n", results[s].naive_ms);

        /* Benchmark KMP Search */
        printf("      Running KMP search        ... ");
        fflush(stdout);
        clock_t start_kmp = clock();
        scan_benchmark(filename, signatures, sig_count, ALGO_KMP);
        clock_t end_kmp = clock();
        results[s].kmp_ms = ((double)(end_kmp - start_kmp) * 1000.0) / CLOCKS_PER_SEC;
        printf("%.2f ms\n", results[s].kmp_ms);

        /* Benchmark Rabin-Karp Search */
        printf("      Running Rabin-Karp search ... ");
        fflush(stdout);
        clock_t start_rk = clock();
        scan_benchmark(filename, signatures, sig_count, ALGO_RABIN_KARP);
        clock_t end_rk = clock();
        results[s].rk_ms = ((double)(end_rk - start_rk) * 1000.0) / CLOCKS_PER_SEC;
        printf("%.2f ms\n\n", results[s].rk_ms);
    }

    /* Free dynamically allocated sample lines */
    for (int j = 0; j < num_samples; j++) {
        free(sample_lines[j]);
    }

    /* Step 3: Print formatted comparison table of milliseconds per algorithm per size */
    printf("=========================================================================\n");
    printf("              BENCHMARK EXECUTION TIME SUMMARY (Milliseconds)            \n");
    printf("=========================================================================\n");
    printf("| %-12s | %-16s | %-16s | %-16s |\n", "Log Lines", "Naive (ms)", "KMP (ms)", "Rabin-Karp (ms)");
    printf("+--------------+------------------+------------------+------------------+\n");
    for (int s = 0; s < num_sizes; s++) {
        printf("| %-12s | %16.2f | %16.2f | %16.2f |\n",
               size_labels[s],
               results[s].naive_ms,
               results[s].kmp_ms,
               results[s].rk_ms);
    }
    printf("+--------------+------------------+------------------+------------------+\n\n");

    /* Step 4: Save table to result.csv */
    const char *csv_filename = "result.csv";
    FILE *csv_file = fopen(csv_filename, "w");
    if (csv_file == NULL) {
        printf("Error: Could not open '%s' for writing.\n", csv_filename);
    } else {
        fprintf(csv_file, "Lines,Naive (ms),KMP (ms),Rabin-Karp (ms)\n");
        for (int s = 0; s < num_sizes; s++) {
            fprintf(csv_file, "%d,%.2f,%.2f,%.2f\n",
                    results[s].lines,
                    results[s].naive_ms,
                    results[s].kmp_ms,
                    results[s].rk_ms);
        }
        fclose(csv_file);
        printf("Successfully saved benchmark table to '%s'.\n", csv_filename);
    }
    printf("=========================================================================\n");
}

/*
 * Structure to store worst-case benchmark timing results.
 */
typedef struct {
    int size;                    /* Length of text (n copies of 'A') */
    double naive_ms;             /* Average time in milliseconds for Naive search */
    double kmp_ms;               /* Average time in milliseconds for KMP search */
    double rk_ms;                /* Average time in milliseconds for Rabin-Karp search */
    long long naive_comparisons; /* Character comparisons made by Naive search  */
    long long kmp_comparisons;   /* Character comparisons made by KMP search     */
} WorstCaseResult;

/*
 * Function: run_worst_case_benchmark
 * ----------------------------------
 * Tests the theoretical worst-case performance of Naive string matching
 * compared to KMP and Rabin-Karp.
 *
 * Worst-Case Setup:
 *   - Pattern : 100 'A' characters followed by 1 'B' (length 101)
 *   - Text    : n consecutive copies of 'A'
 *
 * Why this is the worst-case for Naive:
 *   At each shift i in the text, Naive compares characters one by one.
 *   The first 100 characters match ('A' == 'A'), but the 101st character
 *   fails ('A' != 'B').
 *   Naive then slides forward by only 1 character and re-evaluates all 100
 *   'A's again! This results in O(n * m) operations (~100 * n comparisons).
 *
 * In contrast:
 *   - KMP uses its LPS table to never backtrack in text -> O(n + m) linear time.
 *   - Rabin-Karp updates rolling hash in O(1) constant time without collisions -> O(n + m).
 *
 * How it runs:
 *   - Each algorithm is run 5 times per size and the AVERAGE time is reported.
 *   - The global 'comparisons' counter is reset before every search, so the
 *     table and worstcase.csv also show how many character comparisons the
 *     Naive and KMP searches performed.
 *
 * Tested Sizes:
 *   n = 10,000, 50,000, 100,000, 200,000, and 1,000,000 characters.
 *
 * Output:
 *   Prints an aligned ASCII table to stdout and saves results to "worstcase.csv".
 */
void run_worst_case_benchmark(void) {
    /*
     * Build the pattern in code: 100 'A' characters followed by one 'B'
     * (length 101). Building it in code is simpler and safer than typing
     * 100 'A's inside a string literal.
     */
    char pattern_buf[103];
    memset(pattern_buf, 'A', 100);
    pattern_buf[100] = 'B';
    pattern_buf[101] = '\0';
    const char *pattern = pattern_buf;

    /* Number of times each algorithm is run per size (average time is reported) */
    const int runs = 5;

    /*
     * Benchmark sizes: 10,000, 50,000, 100,000, 200,000, and 1,000,000.
     * Note: 100,000 and 1,000,000 are both included to cover the 100K progression
     * and the 1M scale.
     */
    const int sizes[] = {10000, 50000, 100000, 200000, 1000000};
    const char *size_labels[] = {"10,000", "50,000", "100,000", "200,000", "1,000,000"};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    WorstCaseResult results[5];

    printf("=========================================================================\n");
    printf("              MINI-IDS WORST-CASE PERFORMANCE BENCHMARK                 \n");
    printf("=========================================================================\n");
    printf("Pattern : 100 'A' characters followed by 'B' (length 101)\n");
    printf("Text    : n copies of 'A' (forces Naive to match 100 chars then fail)\n");
    printf("Sizes   : 10,000, 50,000, 100,000, 200,000, and 1,000,000 characters\n");
    printf("Runs    : each algorithm runs %d times per size, AVERAGE time reported\n", runs);
    printf("Timing   : clock() in milliseconds, plus comparison counts for Naive/KMP\n");
    printf("=========================================================================\n\n");

    for (int s = 0; s < num_sizes; s++) {
        int n = sizes[s];
        results[s].size = n;

        printf("[%d/%d] Testing n = %s characters...\n", s + 1, num_sizes, size_labels[s]);

        /* Allocate text buffer and fill with 'A' */
        char *text = (char *)malloc(n + 1);
        if (text == NULL) {
            printf("Error: Memory allocation failed for size %d\n", n);
            continue;
        }
        memset(text, 'A', n);
        text[n] = '\0';

        /* --- Run every algorithm 'runs' times and average the times --- */
        double naive_total = 0.0, kmp_total = 0.0, rk_total = 0.0;
        long long naive_comps = 0, kmp_comps = 0;

        printf("      Running each algorithm %d times...\n", runs);

        for (int r = 0; r < runs; r++) {
            /* 1. Benchmark Naive Search (counter reset before the search) */
            comparisons = 0;
            clock_t t0 = clock();
            volatile int match_naive = naive_search(text, pattern);
            clock_t t1 = clock();
            (void)match_naive;
            naive_total += ((double)(t1 - t0) * 1000.0) / CLOCKS_PER_SEC;
            naive_comps = comparisons; /* Same input -> same count every run */

            /* 2. Benchmark KMP Search (counter reset before the search) */
            comparisons = 0;
            t0 = clock();
            volatile int match_kmp = kmp_search(text, pattern);
            t1 = clock();
            (void)match_kmp;
            kmp_total += ((double)(t1 - t0) * 1000.0) / CLOCKS_PER_SEC;
            kmp_comps = comparisons; /* Same input -> same count every run */

            /* 3. Benchmark Rabin-Karp Search (no comparison counting for RK) */
            int spurious_hits = 0;
            t0 = clock();
            volatile int match_rk = rabin_karp_search(text, pattern, &spurious_hits);
            t1 = clock();
            (void)match_rk;
            rk_total += ((double)(t1 - t0) * 1000.0) / CLOCKS_PER_SEC;
        }

        /* Store the AVERAGE time and the comparison counts for this size */
        results[s].naive_ms = naive_total / runs;
        results[s].kmp_ms = kmp_total / runs;
        results[s].rk_ms = rk_total / runs;
        results[s].naive_comparisons = naive_comps;
        results[s].kmp_comparisons = kmp_comps;

        printf("        Naive      : %10.2f ms avg | %lld comparisons\n",
               results[s].naive_ms, results[s].naive_comparisons);
        printf("        KMP        : %10.2f ms avg | %lld comparisons\n",
               results[s].kmp_ms, results[s].kmp_comparisons);
        printf("        Rabin-Karp : %10.2f ms avg\n\n", results[s].rk_ms);

        free(text);
    }

    /* Print formatted ASCII table */
    printf("=========================================================================\n");
    printf("            WORST-CASE BENCHMARK EXECUTION TIME SUMMARY (ms)            \n");
    printf("=========================================================================\n");
    printf("| %-15s | %-16s | %-16s | %-16s | %-16s | %-16s |\n",
           "Text Size (n)", "Naive (ms)", "KMP (ms)", "Rabin-Karp (ms)",
           "Naive Compares", "KMP Compares");
    printf("+-----------------+------------------+------------------+------------------+------------------+------------------+\n");
    for (int s = 0; s < num_sizes; s++) {
        printf("| %-15s | %16.2f | %16.2f | %16.2f | %16lld | %16lld |\n",
               size_labels[s],
               results[s].naive_ms,
               results[s].kmp_ms,
               results[s].rk_ms,
               results[s].naive_comparisons,
               results[s].kmp_comparisons);
    }
    printf("+-----------------+------------------+------------------+------------------+------------------+------------------+\n\n");

    /* Save table to worstcase.csv */
    const char *csv_filename = "worstcase.csv";
    FILE *csv_file = fopen(csv_filename, "w");
    if (csv_file == NULL) {
        printf("Error: Could not open '%s' for writing.\n", csv_filename);
    } else {
        fprintf(csv_file, "Size,Naive (ms),KMP (ms),Rabin-Karp (ms),Naive Comparisons,KMP Comparisons\n");
        for (int s = 0; s < num_sizes; s++) {
            fprintf(csv_file, "%d,%.2f,%.2f,%.2f,%lld,%lld\n",
                    results[s].size,
                    results[s].naive_ms,
                    results[s].kmp_ms,
                    results[s].rk_ms,
                    results[s].naive_comparisons,
                    results[s].kmp_comparisons);
        }
        fclose(csv_file);
        printf("Successfully saved worst-case benchmark table to '%s'.\n", csv_filename);
    }
    printf("=========================================================================\n");
}

int main(int argc, char *argv[]) {
    const char *sig_file = "signatures.txt";
    const char *log_file = "logs.txt";

    /* If logs.text exists, prefer it, otherwise use logs.txt */
    FILE *check_log = fopen("logs.text", "r");
    if (check_log != NULL) {
        log_file = "logs.text";
        fclose(check_log);
    }

    Signature signatures[MAX_SIGNATURES];

    /* Step 1: Load signatures from signatures.txt */
    int sig_count = load_signatures(sig_file, signatures, MAX_SIGNATURES);
    if (sig_count < 0) {
        return 1; /* Failed to open signatures file */
    }

    printf("Successfully loaded %d attack signatures from '%s'.\n\n", sig_count, sig_file);

    /* Step 2: Choose algorithm or benchmark mode at runtime (interactive prompt or CLI argument) */
    AlgorithmType algo = choose_algorithm(argc, argv);

    /* Step 3: Scan web server logs against the signatures using the chosen algorithm / mode */
    if (algo == ALGO_BENCHMARK) {
        run_benchmark(signatures, sig_count);
    } else if (algo == ALGO_WORST_CASE) {
        run_worst_case_benchmark();
    } else {
        scan_logs(log_file, signatures, sig_count, algo);
    }

    return 0;
}
