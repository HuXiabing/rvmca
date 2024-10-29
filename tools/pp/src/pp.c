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

int main(int argc, char *argv[]) {
    FILE *file;
    char lines[MAX_INSN][1024];
    // 检查是否有足够的命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // 打开文件
    file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    int i = 0;
    // 按行读取文件
    while (fgets(lines[i], sizeof(lines[i]), file) != NULL) {
        // 去除行尾的换行符
        lines[i][strcspn(lines[i], "\n")] = 0;
        // 检查行是否为空或仅包含空格和回车
        if (!is_empty_or_space(lines[i])) {
            i++;
        }

        if(i>=MAX_INSN){
            break;
        }
    }

    printf("<Block>:\n");

    uint32_t *insn_ptr = &profile_insn_start;
    // 关闭文件
    fclose(file);
    if (i>MAX_INSN){
        printf("Error: the number of input instructions is more than %d.\n", MAX_INSN);
        return EXIT_FAILURE;
    }

    for(int k=0;k<i;k++){
        uint32_t encode = strtol(lines[k], NULL, 16);
        // skip jump instruction
        if((encode & MASK_JALR) == MATCH_JALR || (encode & MASK_JAL) == MATCH_JAL)
            break;
        printf("%s\n", lines[k]);
        (* insn_ptr) = encode;
        insn_ptr++;
    }
    (* insn_ptr) = __COUNT_END_CODE;

    printf("\n");

    ENABLE_FPU
    ENABLE_VPU

    init_fpu();
    long minN = LONG_MAX, min0 = LONG_MAX;
    for (int i = 0; i < 10; i++) {
        run(&minN,&min0);
        printf("[%d]: %ld - %ld\n", i, minN, min0);
    }

    
    printf("\ncycles: %ld\n", minN - min0);

    return EXIT_SUCCESS;
}