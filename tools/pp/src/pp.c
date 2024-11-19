#include "pp.h"
#include <limits.h>

__attribute__((noinline)) void run(long *min1, long *min2) {
    long result1 = 0, result2 = 0;
    
    result1 = profileN(); 
    result2 = profile0();
    *min1 = (result1 < *min1) ? result1 : *min1;
    *min2 = (result2 < *min2) ? result2 : *min2;
}

int is_empty_or_space(const char *str) {
    // 检查字符串是否为空或仅包含空格和回车
    while (*str) {
        if (!isspace((unsigned char)*str)) {
            return 0; // 包含非空格/回车的字符
        }
        str++;
    }
    return 1; // 仅包含空格/回车或为空
}

char lines[MAX_INSN][1024];

int read_insns_from_file(FILE* file){
    int i = 0;
    // 按行读取文件
    while (fgets(lines[i], sizeof(lines[i]), file) != NULL) {
        // 去除行尾的换行符
        lines[i][strcspn(lines[i], "\n")] = 0;
        // 检查行是否为空或仅包含空格和回车
        if (!is_empty_or_space(lines[i]))
            i++;
        if(i>=MAX_INSN)
            break;
    }
    return i;
}

int main(int argc, char *argv[]) {
    // check the number of arguments
    if (argc != 3){
        fprintf(stderr, "Usage: %s xxx.init xxx.code\n", argv[0]);
        fprintf(stderr, "  xxx.init and xxx.code are required\n", argv[0]);

        return EXIT_FAILURE;
    }

    // insert init code to profile.S
    FILE *file;
    char *init_filename = argv[1];
    char *test_filename = argv[2];


    file = fopen(init_filename, "r");
    if (file == NULL) {
        printf("File %s not found.\n", init_filename);
        printf("Skip the initialization.\n\n");
    }else{
        int length = read_insns_from_file(file);
        fclose(file);
        printf("<Init Code>:\n");

        uint32_t *insn_ptr = &profile_insn_init;

        if (length>MAX_INSN){
            printf("Error: the number of input instructions is more than %d.\n", MAX_INSN);
            return EXIT_FAILURE;
        }

        for(int k=0;k<length;k++){
            uint32_t encode = strtol(lines[k], NULL, 16);
            printf("%s\n", lines[k]);
            (* insn_ptr) = encode;
            insn_ptr++;
        }
    }

    // insert test code to profile.S
    file = fopen(test_filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    int length = read_insns_from_file(file);
    fclose(file);
    if (length>MAX_INSN){
        printf("Error: the number of input instructions is more than %d.\n", MAX_INSN);
        return EXIT_FAILURE;
    }

    printf("\n<Block>:\n");
    for(int k=0;k<length;k++){
        printf("%s\n", lines[k]);
    }
    uint32_t *insn_ptr = &profile_insn_start;
    for(int k=0;k<length;k++){
        uint32_t encode = strtol(lines[k], NULL, 16);
        // skip jump instruction
        if((encode & MASK_JALR) == MATCH_JALR || (encode & MASK_JAL) == MATCH_JAL)
            break;
        if(encode == 0xc00027f3){
            perror("Do not use the profiling instruction 'rdcycle a5'.\n");
            return EXIT_FAILURE;
        }
        (* insn_ptr) = encode;
        insn_ptr++;
    }
    (* insn_ptr) = __COUNT_END_CODE;

    printf("\n");

    ENABLE_FPU
    ENABLE_VPU

    init_fpu();
    long minN = LONG_MAX, min0 = LONG_MAX;
    for (int i = 0; i < 100; i++){
        run(&minN,&min0);
        printf("[%d]: %ld - %ld\n", i, minN, min0);
    }

    
    printf("\ncycles: %ld\n", minN - min0);

    return EXIT_SUCCESS;
}