#define _GNU_SOURCE

#include "pp.h"
#include <limits.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>

static void segv_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    unsigned long *g = uc->uc_mcontext.__gregs;

    fprintf(stderr,
            "pp: SIGSEGV pc=0x%lx fault=0x%lx sp=0x%lx gp=0x%lx "
            "ra=0x%lx a0=0x%lx a4=0x%lx a5=0x%lx t6=0x%lx\n",
            g[REG_PC], (unsigned long)info->si_addr, g[REG_SP], g[3],
            g[REG_RA], g[REG_A0], g[14], g[15], g[31]);
    _exit(128 + sig);
}

static void install_signal_handlers(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
}

__attribute__((noinline)) void run(long *min1, long *min2) {
    unsigned long result1 = 0, result2 = 0;
    
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
    char buf[1024];

    while (fgets(buf, sizeof(buf), file) != NULL) {
        buf[strcspn(buf, "\n")] = 0;
        if (is_empty_or_space(buf))
            continue;
        if (i >= MAX_INSN)
            return MAX_INSN + 1;
        strncpy(lines[i], buf, sizeof(lines[i]) - 1);
        lines[i][sizeof(lines[i]) - 1] = 0;
        i++;
    }
    return i;
}

int main(int argc, char *argv[]) {
    install_signal_handlers();

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
        (* insn_ptr) = encode;
        insn_ptr++;
    }
    (* insn_ptr) = __COUNT_END_CODE;

    printf("\n");

    init_fpu();
    ENABLE_FPU
//    ENABLE_VPU
    unsigned long minN = LONG_MAX, min0 = LONG_MAX;
    for (int i = 0; i < 100; i++){
        run(&minN,&min0);
        printf("[%d]: %ld - %ld\n", i, minN, min0);
    }

    
    printf("\ncycles: %ld\n", minN - min0);

    return EXIT_SUCCESS;
}
