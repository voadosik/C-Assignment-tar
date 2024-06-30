#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 512

struct posix_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
};

void print_usage() {
    fprintf(stderr, "Usage: mytar -f <archive> -t [list of files]\n");
    fprintf(stderr, "       mytar -f <archive> -x [-v] [list of files]\n");
}

void exit_with_error(int exit_code, const char *message, int suppress_failure_status_message) {
    if (message) {
        fprintf(stderr, "mytar: %s\n", message);
    }
    if (exit_code == 2 && !suppress_failure_status_message) {
        fprintf(stderr, "mytar: Exiting with failure status due to previous errors\n");
    }
    exit(exit_code);
}

int is_zero_block(const char *block) {
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        if (block[i] != '\0') {
            return 0;
        }
    }
    return 1;
}

void parse_arguments
(int argc, char *argv[], int *t_flag, int *f_flag, int *x_flag, int *v_flag,
const char **archive_name, const char ***files_to_list, int *num_files_to_list) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'f':
                    if (++i >= argc) {
                        exit_with_error(2, "option requires an argument -- 'f'", 0);
                    }
                    *f_flag = 1;
                    *archive_name = argv[i];
                    break;
                case 't':
                    *t_flag = 1;
                    break;
                case 'x':
                    *x_flag = 1;
                    break;
                case 'v':
                    *v_flag = 1;
                    break;
                default:
                    exit_with_error(2, "Unknown option", 0);
            }
        } else if (*t_flag || *x_flag) {
            *files_to_list = (const char **)(argv + i);
            *num_files_to_list = argc - i;
            break;
        }
    }
}

void check_required_flags(int f_flag, int t_flag, int x_flag) {
    if (!f_flag) {
        exit_with_error(2, "No archive file specified", 0);
    }
    if (!t_flag && !x_flag) {
        exit_with_error(2, "need at least one option", 0);
    }
}

void process_archive(FILE *archive, const char **files_to_list, int num_files_to_list, int *exit_code, int *suppress_failure_status_message, int t_flag, int x_flag, int v_flag) {
    char block[BLOCK_SIZE];
    struct posix_header header;
    int num_zero_blocks = 0;
    int lone_zero_block_warning = 0;
    size_t bytes_read;

    while ((bytes_read = fread(&header, 1, BLOCK_SIZE, archive)) == BLOCK_SIZE) {
        if (is_zero_block((const char*)&header)) {
            num_zero_blocks++;
            if (num_zero_blocks == 2) break;
            continue;
        } else {
            if (num_zero_blocks == 1 && !lone_zero_block_warning) {
                fprintf(stderr, "mytar: A lone zero block at %ld\n", ftell(archive) / BLOCK_SIZE - 1);
                lone_zero_block_warning = 1;
            }
            num_zero_blocks = 0;
        }

        if (strncmp(header.magic, "ustar", 5) != 0) {
            fprintf(stderr, "mytar: This does not look like a tar archive\n");
            *exit_code = 2;
            *suppress_failure_status_message = 1;
            exit_with_error(2, NULL, 0);
            break;
        }

        unsigned long long file_size = strtoull(header.size, NULL, 8);
        int num_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

        if (header.typeflag != '0') {
            fprintf(stderr, "mytar: Unsupported header type: %d\n", header.typeflag);
            *exit_code = 2;
            *suppress_failure_status_message = 1;
            break;
        }

        if (t_flag) {
            if (num_files_to_list > 0) {
                for (int i = 0; i < num_files_to_list; ++i) {
                    if (files_to_list[i] && strcmp(header.name, files_to_list[i]) == 0) {
                        printf("%s\n", header.name);
                        files_to_list[i] = "";
                        break;
                    }
                }
            } else {
                printf("%s\n", header.name);
            }
        }

        if (x_flag) {
            int extract_file = (num_files_to_list == 0);
            if (!extract_file) {
                for (int i = 0; i < num_files_to_list; ++i) {
                    if (files_to_list[i] && strcmp(header.name, files_to_list[i]) == 0) {
                        extract_file = 1;
                        files_to_list[i] = "";
                        break;
                    }
                }
            }

            if (extract_file) {
                if (v_flag) {
                    printf("%s\n", header.name);
                }

                FILE *outfile = fopen(header.name, "wb");
                if (!outfile) {
                    fprintf(stderr, "mytar: Cannot create file %s\n", header.name);
                    *exit_code = 2;
                    *suppress_failure_status_message = 1;
                    break;
                }

                unsigned long long remaining_size = file_size;
                for (int i = 0; i < num_blocks; ++i) {
                    size_t bytes_to_read = (remaining_size < BLOCK_SIZE) ? remaining_size : BLOCK_SIZE;
                    size_t actual_bytes_read = fread(block, 1, BLOCK_SIZE, archive);
                    if (actual_bytes_read != BLOCK_SIZE) {
                        fprintf(stderr, "mytar: Unexpected EOF in archive\n");
                        fprintf(stderr, "mytar: Error is not recoverable: exiting now\n");
                        *suppress_failure_status_message = 1;
                        fclose(outfile);
                        exit_with_error(2, NULL, *suppress_failure_status_message);
                    }
                    fwrite(block, 1, bytes_to_read, outfile);
                    remaining_size -= bytes_to_read;
                }
                fclose(outfile);
            } else {
                for (int i = 0; i < num_blocks; ++i) {
                    if (fread(block, 1, BLOCK_SIZE, archive) != BLOCK_SIZE) {
                        fprintf(stderr, "mytar: Unexpected EOF in archive\n");
                        fprintf(stderr, "mytar: Error is not recoverable: exiting now\n");
                        *suppress_failure_status_message = 1;
                        exit_with_error(2, NULL, *suppress_failure_status_message);
                    }
                }
            }
        } else {
            for (int i = 0; i < num_blocks; ++i) {
                if (fread(block, 1, BLOCK_SIZE, archive) != BLOCK_SIZE) {
                    fprintf(stderr, "mytar: Unexpected EOF in archive\n");
                    fprintf(stderr, "mytar: Error is not recoverable: exiting now\n");
                    *suppress_failure_status_message = 1;
                    exit_with_error(2, NULL, *suppress_failure_status_message);
                }
            }
        }
    }

    for (int i = 0; i < num_files_to_list; ++i) {
        if (files_to_list[i] && files_to_list[i][0] != '\0') {
            fprintf(stderr, "mytar: %s: Not found in archive\n", files_to_list[i]);
            *exit_code = 2;
        }
    }

    if (num_zero_blocks == 1 && !lone_zero_block_warning) {
        fprintf(stderr, "mytar: A lone zero block at %ld\n", ftell(archive) / BLOCK_SIZE);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage();
        exit_with_error(2, "need at least one option", 0);
    }

    const char *archive_name = NULL;
    const char **files_to_list = NULL;
    int num_files_to_list = 0;
    int t_flag = 0;
    int f_flag = 0;
    int x_flag = 0;
    int v_flag = 0;
    int exit_code = 0;
    int suppress_failure_status_message = 0;
    int other_errors_occurred = 0;

    parse_arguments(argc, argv, &t_flag, &f_flag, &x_flag, &v_flag, &archive_name, &files_to_list, &num_files_to_list);
    check_required_flags(f_flag, t_flag, x_flag);

    FILE *archive = fopen(archive_name, "rb");
    if (!archive) {
        exit_with_error(2, "cannot open archive file", 0);
    }

    process_archive(archive, files_to_list, num_files_to_list, &exit_code, &suppress_failure_status_message, t_flag, x_flag, v_flag);

    if (archive) {
        fclose(archive);
    }

    if (other_errors_occurred) {
        suppress_failure_status_message = 0;
    }

    exit_with_error(exit_code, NULL, suppress_failure_status_message);
    return exit_code;
}
