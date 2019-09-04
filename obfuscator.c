/**
 * @author evilyach@protonmail.com.
 *
 * @disclaimer
 * This project is only for educational puproses.
 * Usage of this for attacking purposes without prior mutual consent is illegal.
 * It is the end user's responsibility to obey all applicable local, state or
 * federal laws. I, as a developer, assume no liability and am not responsible
 * for any misuse or damage caused by this program.
 *
 * @brief
 * This project allows to obfuscate any executable code by creating filler
 * functions and putting them all into filler ELF-sections. This allows to
 * bypass any signature scans by antivirus and allows to make static analysis
 * of an executable much harder task.
 * This only works on Linux machines.
 *
 * @usage
 * You can either use a premade executable file or use source code.
 * TODO:
 *
 * @note
 * It is far from being done, and runtime compling is not done yet, which is the
 * purpose of this program.
 */

#define _XOPEN_SOURCE 500
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof x / sizeof *x)
#define pass (void) NULL

uint32_t random_number;
char **filenames_array;


/* ========================================================================= */

/**
 * This section of a file consists of different statements that a compilable
 * C program can consist of. They get filled with random numbers to make
 * analysis of a program much harder.
 */

const char *statements_includes[] = {
    "#include <stdlib.h>\n",
    "#include <string.h>\n",
    "#include <fcntl.h>\n",
    "#include <ftw.h>\n",
    "#include <inttypes.h>\n",
    "#include <math.h>\n",
};

const char *statements_functions_1_param[] = {
    "static void p%u(void) {\n",
    "static int p%u(void) {\n",
    "static char p%u(void) {\n",
    "static const char *p%u(void) {\n",
    "static long long *p%u(void) {\n",
    "static float *p%u(void) {\n",
};

const char *statements_functions_2_param[] = {
    "static void p%u(int p%u) {\n",
    "static int p%u(int p%u) {\n",
    "static char p%u(int p%u) {\n",
    "static const char *p%u(int p%u) {\n",
    "static long long p%u(int p%u) {\n",
    "static float p%u(int p%u) {\n",
    "static void p%u(float p%u) {\n",
    "static int p%u(float p%u) {\n",
    "static char p%u(float p%u) {\n",
    "static const char *p%u(float p%u) {\n",
    "static long long p%u(float p%u) {\n",
    "static float p%u(float p%u) {\n",
};

const char *statements_functions_3_param[] = {
    "static void p%u(int p%u, float p%u) {\n",
    "static int p%u(int p%u, float p%u) {\n",
    "static char p%u(int p%u, float p%u) {\n",
    "static const char *p%u(int p%u, float p%u) {\n",
    "static long long p%u(int p%u, float p%u) {\n",
    "static float p%u(int p%u, float p%u) {\n",
    "static void p%u(int p%u, const char *s%u) {\n",
    "static int p%u(int p%u, const char *s%u) {\n",
    "static char p%u(int p%u, const char *s%u) {\n",
    "static const char *p%u(int p%u, const char *s%u) {\n",
    "static long long p%u(int p%u, const char *s%u) {\n",
    "static float p%u(int p%u, const char *s%u) {\n",
    "static void p%u(char c%u, float p%u) {\n",
    "static int p%u(char c%u, float p%u) {\n",
    "static char p%u(char c%u, float p%u) {\n",
    "static const char *p%u(char c%u, float p%u) {\n",
    "static long long p%u(char c%u, float p%u) {\n",
    "static float p%u(char c%u, float f%u) {\n",
};

const char *statements_1_param[] = {
    "int i%d;\n",
    "float f%d;\n",
    "char c%d;\n",
    "puts(\"%d\");\n",
    "puts(\"%u\");\n",
    "if (%d) {}\n",
};

const char *statements_2_param[] = {
    "int i%u = %d;\n",
    "int i%u = -%u;\n",
    "int i%u = !%u;\n",
    "char c%u = %d;\n",
    "unsigned u%u = %d;\n",
    "unsigned char uc%u = %d;\n",
    "long l%u = %d;\n",
    "long long ll%u = %d;\n",
    "float f%u = %d;\n",
    "const char *s%u = \"%d\";\n",
    "int ia%u[%d];\n",
    "struct { int i%u; } d%u;\n",
    "struct { const char *s%u; } d%u;\n",
    "if (%d) puts(\"%d\");\n",
    "while (%d) puts(\"%d\");\n",
    "do { puts(\"%d\"); } while (%d);\n",
};

const char *statements_3_param[] = {
    "int i%u = %d + %d;\n",
    "int i%u = %d - %d;\n",
    "int i%u = %d * %d;\n",
    "float f%u = %d / %d;\n",
    "int i%u = %d & %d;\n",
    "int i%u = %d | %d;\n",
    "int i%u = %d ^ %d;\n",
    "struct { int i%u; const char *s%u; } struct%u;\n",
    "char i%u = %d + %d;\n",
    "char i%u = %d - %d;\n",
    "char i%u = %d * %d;\n",
    "char i%u = %d & %d;\n",
    "char i%u = %d | %d;\n",
    "char i%u = %d ^ %d;\n",
    "long long i%u = %d + %d;\n",
    "long long i%u = %d - %d;\n",
    "long long i%u = %d * %d;\n",
    "long long i%u = %d & %d;\n",
    "long long i%u = %d | %d;\n",
    "long long i%u = %d ^ %d;\n",
    "if (%d == %d) puts(\"%d\");\n",
    "if (%d > %d) puts(\"%d\");\n",
    "if (%d < %d) puts(\"%d\");\n",
    "if (%d != %d) puts(\"%d\");\n",
    "if (!(%d + %d)) puts(\"%d\");\n",
    "while (%d == %d) puts(\"%d\");\n",
    "while (%d > %d) puts(\"%d\");\n",
    "while (%d < %d) puts(\"%d\");\n",
    "while (%d != %d) puts(\"%d\");\n",
    "while (!(%d + %d)) puts(\"%d\");\n",
    "do { puts(\"%d\"); } while (%d == %d);\n",
    "do { puts(\"%d\"); } while (%d > %d);\n",
    "do { puts(\"%d\"); } while (%d < %d);\n",
    "do { puts(\"%d\"); } while (%d != %d);\n",
    "do { puts(\"%d\"); } while (!(%d + %d));\n",
};


/* ========================================================================= */


/**
 * @brief Generate the header part of a C source file.
 *
 * @param fd - file decriptor.
 *
 * @retval  0 - success.
 * @retval -1 - error occurred.
 */
static int generate_header(int fd)
{
    /* Always include stdio.h */
    const char *stdio_include = "#include <stdio.h>\n";
    write(fd, stdio_include, strlen(stdio_include));

    /* Generate random include */
    getrandom(&random_number, sizeof(uint32_t), 0);
    uint32_t index = (random_number) % ARRAY_SIZE(statements_includes);
    write(fd, statements_includes[index], strlen(statements_includes[index]));

    write(fd, "\n", 1);

    /* Generate zero or one global variables */
    getrandom(&random_number, sizeof(uint32_t), 0);
    char string[255];
    snprintf(string, 255, statements_2_param[0], random_number, random_number / 2);
    (random_number % 2 == 0) ? write(fd, string, strlen(string)) : pass;

    write(fd, "\n", 1);

    return 0;
}


/**
 * @brief Generate the main part of a C file, containing several functions.
 *
 * @param fd - file descriptor.
 *
 * @retval  0 - success.
 * @retval -1 - error occurred.
 */
static int generate_functions(int fd)
{
    getrandom(&random_number, sizeof(uint32_t), 0);
    uint32_t index;
    int section = random_number / 3;
    int func_name;

    for (int i = 0; i < random_number % 20; i++) {
        /* Generate function header */
        char string_func[256];
        switch (random_number % 3) {
            case 0:
                getrandom(&random_number, sizeof(uint32_t), 0);
                index = (random_number) % ARRAY_SIZE(statements_functions_1_param);
                func_name = random_number;
                snprintf(string_func, 256, statements_functions_1_param[index],
                        func_name);
                write(fd, string_func, strlen(string_func));
                break;

            case 1:
                getrandom(&random_number, sizeof(uint32_t), 0);
                index = (random_number) % ARRAY_SIZE(statements_functions_2_param);
                func_name = random_number;
                snprintf(string_func, 256, statements_functions_2_param[index],
                        func_name, func_name ^ section);
                write(fd, string_func, strlen(string_func));
                break;

            case 2:
                getrandom(&random_number, sizeof(uint32_t), 0);
                index = (random_number) % ARRAY_SIZE(statements_functions_3_param);
                func_name = random_number;
                snprintf(string_func, 256, statements_functions_3_param[index],
                        func_name, func_name ^ section, func_name ^ (section / 2));
                write(fd, string_func, strlen(string_func));
                break;

            default:
                break;
        }

        /* Generate random calls inside a function */
        char temp[256];
        char string_call[256];

        getrandom(&random_number, sizeof(uint32_t), 0);
        for (uint32_t j = 5; j < 5 + random_number % 1000; j++) {
            switch (random_number % 3) {
                case 0:
                    getrandom(&random_number, sizeof(uint32_t), 0);
                    index = (i * j) % ARRAY_SIZE(statements_1_param);
                    snprintf(temp, 1024, "\t%s", statements_1_param[index]);
                    snprintf(string_call, 1024, temp, random_number % 1349);
                    write(fd, string_call, strlen(string_call));
                    break;

                case 1:
                    getrandom(&random_number, sizeof(uint32_t), 0);
                    index = (i * j) % ARRAY_SIZE(statements_2_param);
                    snprintf(temp, 1024, "\t%s", statements_2_param[index]);
                    snprintf(string_call, 1024, temp,
                            (random_number) % 1349, (random_number * j) % 1349);
                    write(fd, string_call, strlen(string_call));
                    break;

                case 2:
                    getrandom(&random_number, sizeof(uint32_t), 0);
                    index = (i * j) % ARRAY_SIZE(statements_3_param);
                    snprintf(temp, 1024, "\t%s", statements_3_param[index]);
                    snprintf(string_call, 1024, temp,
                            (random_number) % 1349, (random_number * j) % 1349, (random_number * i * j) % 1349);
                    write(fd, string_call, strlen(string_call));
                    break;

                default:
                    break;
            }
        }

        /* Close a function */
        write(fd, "}\n\n", 3);

        /* Generate a struct with a callback */
        char struct_def_base[] = \
            "typedef void (*cb_%u_t)(const char *);\n"
            "\n"
            "struct info_%u {\n"
            "\tcb_%u_t fn;\n"
            "\tchar *name;\n"
            "};\n"
            "\n"
            "static struct info_%u __info_%u\n"
            "__attribute__((section(\"sec%d\")))\n"
            "__attribute__((used)) = {\n"
            "\t.fn = p%u,\n"
            "\t.name = \"p%u\",\n"
            "}; \n\n";

        char struct_def[1024];
        snprintf(struct_def, 1024, struct_def_base,
                 func_name, func_name, func_name, func_name,
                 func_name, section, func_name, func_name);

        write(fd, struct_def, strlen(struct_def));
    }

    return 0;
}


/**
 * @brief Fill a file with random statements that make it compilable.
 *
 * @param name - name of a file in a filesystem.
 *
 * @retval  0 - success.
 * @retval -1 - error occurred.
 */
static int fill_file(const char *name)
{
    int fd = open(name, O_WRONLY, 0700);

    generate_header(fd);
    generate_functions(fd);

    close(fd);
}


/**
 * @brief Create a compilable C file.
 *
 * @param i - index of a file in a for loop.
 *
 * @retval  0 - success.
 * @retval -1 - error occurred.
 */
static int create_c_file(int i)
{
    /* Get a random number to form a basename */
    getrandom(&random_number, sizeof(uint32_t), 0);
    uint32_t basename = random_number;

    /* Create a filename */
    char filename[256];
    memset(filename, 0, 256);
    snprintf(filename, 255, "%u.c", basename);

    /* Create a file */
    creat(filename, 0700);

    /* Write a filename to a filenames array */
    int filename_size = 3 + strlen(filename) + 1;
    char section_name[filename_size];
    snprintf(section_name, filename_size, "sec%u\0", filename);
    filenames_array[i] = malloc(filename_size);
    strcpy(filenames_array[i], filename);

    /* Fill a file with contents */
    fill_file(filename);

    return 0;
}


/**
 * @brief Create a makefile to compile with.
 *
 * @param count - Amount of functions to add to Makefile.
 *
 * @retval  0 - success.
 * @retval -1 - error occurred.
 */
static int create_makefile(int count)
{
    int fd = open("Makefile", O_WRONLY | O_CREAT, 0700);

    const char *makefile_contents_base = \
        "all: all_sections\n"
        "\n"
        "all_sections:\n"
        "\ngcc -o a.out -O0 %s\n";

    /* Getting size of all the strings in filenames_array */
    int filenames_array_size = 0;
    for (int i = 0; i < count; filenames_array_size += sizeof(filenames_array[i]), i++);

    /* Filling sections_str string, containing all the source filenames */
    char sections_str[filenames_array_size];
    for (int i = 0; i < count; i++) {
        printf("sections_str -> %s, filenames_array[%d] -> %s\n", sections_str, i, filenames_array[i]);

        int temp_size = strlen(filenames_array[i]) + 1;
        char temp[temp_size];
        snprintf(temp, temp_size, "%s ", filenames_array[i]);

        strcat(sections_str, temp);
    }
    snprintf(sections_str, strlen(filenames_array[count - 1]), "%s%s\0", sections_str, filenames_array[count - 1]);

    /* Filling the contents */
    int makefile_contents_size = strlen(makefile_contents_base) + count;
    char makefile_contents[makefile_contents_size];
    snprintf(makefile_contents, makefile_contents_size, makefile_contents_base, sections_str);

    write(fd, makefile_contents, makefile_contents_size);

    close(fd);

    return 0;
}


/**
 * @brief Callback that deletes a file it was called with.
 *
 * @note For use with nftw() call.
 *
 * @param name     - name of a file to delete.
 * @param st       - file stats struct.
 * @param typeflag - flag of a filetype.
 * @param ftwbuf   - some struct.
 *
 * @note "Structure used for fourth argument to callback function for `nftw'",
 *       this is what fucking docs say, they don't even know what the fuck is this and
 *       why it is there, just 4th argument.
 *
 * @retval  0 - on success.
 * @retvak -1 - error occurred.
 */
/* Callback to call when going through a directory tree. */
int unlink_cb(const char *name, const struct stat *st, int typeflag, struct FTW *ftwbuf)
{
    int result = remove(name);

    if (result == -1)
        fprintf(stderr, "Could not delete file '%s': '%s'\n", name, strerror(errno));

    return result;
}


/**
 * @brief Application modes: you can obfuscate already compiled executable or
 *        compile from source.
 */
enum {
    FROM_EXECUTABLE,
    FROM_SOURCE,
} MODE;


int main(int argc, char *argv[])
{
    /* Checking arguments and acting accordingly */
    const char *usage = "Usage: %s -m [mode: source or executable] -f [filename...]\n";

    if (argc == 1 || argc > 5) {
        fprintf(stderr, usage, argv[0]);
        return -1;
    }

    const char *filename = argv[5];
    int mode;
    if (strcmp(argv[3], "executable")) {
        mode = FROM_EXECUTABLE;
    } else if (strcmp(argv[3], "source")) {
        mode = FROM_SOURCE;
    } else {
        fprintf(stderr, usage, argv[0]);
        return -1;
    }

    /* Trying to create a directory and move in */
    getrandom(&random_number, sizeof(uint32_t), 0);
    char dirname[256];
    memset(dirname, 0, 256);
    snprintf(dirname, 255, "%u", random_number);

    printf("Trying to create a directory '%u'.\n", dirname);

    nftw(dirname, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);

    if (mkdir(dirname, 0700) == -1) {
        fprintf(stderr, "Could not make directory '%s': '%s'\n", dirname, strerror(errno));
        return -1;
    }

    printf("Directory '%u' successfully created.\n", dirname);

    if (chdir(dirname) == -1) {
        fprintf(stderr, "Could not change directory into '%s': '%s'\n", dirname, strerror(errno));
        return -1;
    }

    printf("Changed directory to '%u'.\n", dirname);

    /* Generate random compilable C source files */
    getrandom(&random_number, sizeof(uint32_t), 0);
    int function_count = random_number % 1000 + 100;
    filenames_array = malloc(function_count * sizeof(char *));

    printf("Generating '%d' random_number files.\n", function_count);

    for (int i = 0; i < function_count; i++) {
        create_c_file(i);
    }

    create_makefile(function_count);

    /* Clean up */
    for (int i = 0; i < function_count; free(filenames_array[i]), i++);
    free(filenames_array);

    return 0;
}
