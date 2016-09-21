//#define NDKLOG

#include <string.h>
#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <elf.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "android_log.h"

extern "C" {

    typedef struct _funcInfo{
        Elf32_Addr st_value;
        Elf32_Word st_size;
    }funcInfo;


    bool sub_1527(JNIEnv *env, jobject thiz, jstring txt);

    static JNINativeMethod gMehtods[] = {
            {"checkStr","(Ljava/lang/String;)Z",(void*) sub_1527}
    };

    static int method_table_size = sizeof(gMehtods) / sizeof (gMehtods[0]);

    static void decstr(char *data, int len){
        for(int i=0; i<len; i++){
            data[i] = ~data[i];
            LOGE("i=%d, %d", i, data[i]);
        }
        LOGE("dec:%s", data);
    }


    bool sub_1527(JNIEnv *env, jobject thiz, jstring txt){
        const char *nativeString = env->GetStringUTFChars(txt, JNI_FALSE);

        char ttt[] = {149,138,223,151,138,158,223,134,150,223,149,150,145,255};
        int lttt = sizeof(ttt)/sizeof(ttt[0]);
        decstr(ttt,lttt);

        bool flag = true;
        int len = strlen(nativeString);
        if (len == strlen(ttt)) {
            for (int i = 0; i < len; i++) {
                if (nativeString[i] != ttt[i]) {
                    flag = false;
                    break;
                }
            }
        } else {
            flag = false;
        }
        env->ReleaseStringUTFChars(txt, nativeString);
        return flag;
    }

    static jint reg(JNIEnv *env){
        jclass dataClass = env->FindClass("com/andr0day/crackme/MainActivity");
        if (!env->RegisterNatives(dataClass, gMehtods,method_table_size) < 0) {
            return -1;
        }
        return 0;
    }

    jint JNI_OnLoad(JavaVM *vm, void *reserved) {
        JNIEnv* env = NULL;
        if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_4) != JNI_OK) {
            return -1;
        }

        if(reg(env)<0){
            return -1;
        }

        return JNI_VERSION_1_4;
    }


    static unsigned elfhash(const char *_name) {
        const unsigned char *name = (const unsigned char *) _name;
        unsigned h = 0, g;

        while(*name) {
            h = (h << 4) + *name++;
            g = h & 0xf0000000;
            h ^= g;
            h ^= g >> 24;
        }
        return h;
    }

    static unsigned long getLibAddr(){
        char name[] = "libcrack.so";
        unsigned long ret = 0;
        char buf[4096], *temp;
        int pid;
        FILE *fp;
        pid = getpid();
        sprintf(buf, "/proc/%d/maps", pid);
        fp = fopen(buf, "r");
        if(fp == NULL)
        {
            LOGE("open failed");
        } else{
            while(fgets(buf, sizeof(buf), fp)){
                if(strstr(buf, name)){
                    temp = strtok(buf, "-");
                    ret = strtoul(temp, NULL, 16);
                    break;
                }
            }
        }
        fclose(fp);
        return ret;
    }

    static char getTargetFuncInfo(unsigned long base, const char *funcName, funcInfo *info){
        char flag = -1, *dynstr;
        int i;
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        Elf32_Off dyn_vaddr;
        Elf32_Word dyn_size, dyn_strsz;
        Elf32_Dyn *dyn;
        Elf32_Addr dyn_symtab, dyn_strtab, dyn_hash;
        Elf32_Sym *funSym;
        unsigned funHash, nbucket;
        unsigned int *bucket, *chain;

        ehdr = (Elf32_Ehdr *)base;
        phdr = (Elf32_Phdr *)(base + ehdr->e_phoff);
        for (i = 0; i < ehdr->e_phnum; ++i) {
            if(phdr->p_type ==  PT_DYNAMIC){
                flag = 0;
                LOGE("Find .dynamic segment");
                break;
            }
            phdr ++;
        }
        if(flag==-1){
            return -1;
        }
        dyn_vaddr = phdr->p_vaddr + base;
        dyn_size = phdr->p_filesz;
        LOGE("dyn_vadd =  0x%x, dyn_size =  0x%x", dyn_vaddr, dyn_size);
        flag = 0;
        int dyn_num = dyn_size/ sizeof(Elf32_Dyn);
        for (i = 0; i < dyn_num; ++i) {
            dyn = (Elf32_Dyn *)(dyn_vaddr + i * sizeof(Elf32_Dyn));
            if(dyn->d_tag == DT_SYMTAB){
                dyn_symtab = (dyn->d_un).d_ptr;
                flag += 1;
                LOGE("Find .dynsym section, addr = 0x%x\n", dyn_symtab);
            }
            if(dyn->d_tag == DT_HASH){
                dyn_hash = (dyn->d_un).d_ptr;
                flag += 2;
                LOGE("Find .hash section, addr = 0x%x\n", dyn_hash);
            }
            if(dyn->d_tag == DT_STRTAB){
                dyn_strtab = (dyn->d_un).d_ptr;
                flag += 4;
                LOGE("Find .dynstr section, addr = 0x%x\n", dyn_strtab);
            }
            if(dyn->d_tag == DT_STRSZ){
                dyn_strsz = (dyn->d_un).d_val;
                flag += 8;
                LOGE("Find strsz size = 0x%x\n", dyn_strsz);
            }
        }
        if((flag & 0x0f) != 0x0f){
            LOGE("Find needed .section failed\n");
            return -1;
        }
        dyn_symtab += base;
        dyn_hash += base;
        dyn_strtab += base;
        dyn_strsz += base;

        LOGE("target:%s",funcName);
        funHash = elfhash(funcName);

        funSym = (Elf32_Sym *) dyn_symtab;
        dynstr = (char*) dyn_strtab;
        nbucket = *((int *) dyn_hash);
        bucket = (unsigned int *)(dyn_hash + 8);
        chain = (unsigned int *)(dyn_hash + 4 * (2 + nbucket));

        LOGE("hash = 0x%x, nbucket = 0x%x\n", funHash, nbucket);
        for(i = bucket[funHash % nbucket]; i != 0; i = chain[i]){
            LOGE("Find index = %d, fun:%s", i,(dynstr + (funSym + i)->st_name));
            if(strcmp(dynstr + (funSym + i)->st_name, funcName) == 0){
                LOGE("Find %s\n", funcName);
                info->st_value = (funSym + i)->st_value;
                info->st_size = (funSym + i)->st_size;
                LOGE("st_value = %d, st_size = %d", info->st_value, info->st_size);
                return 0;
            }
        }
        return -1;
    }


    static void decode(unsigned int base, const char *funcName){
        funcInfo info;
        if(getTargetFuncInfo(base, funcName, &info)==-1){
            LOGE("Find %s failed","JNI_OnLoad");
            return;
        }
        unsigned int npage;
        npage = info.st_size / PAGE_SIZE + ((info.st_size % PAGE_SIZE == 0) ? 0 : 1);
        LOGE("npage:%d, PAGE_SIZE:%d",npage, (int)PAGE_SIZE);
        if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC | PROT_WRITE) != 0){
            LOGE("mem privilege change failed,%s", strerror(errno));
            return;
        }

        for(int i=0;i< info.st_size - 1; i++){
            char *addr = (char*)(base + info.st_value -1 + i);
            *addr = ~(*addr);
        }

        if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC) != 0){
            LOGE("mem privilege change failed,%s", strerror(errno));
            return;
        }
    }

    __attribute__((constructor)) static void decodeFunc(){
        unsigned int base = getLibAddr();
        LOGE("base addr =  0x%x", base);
        // encode sub_1527
        char func[] = {140,138,157,160,206,202,205,200,255};
        int lfunc = sizeof(func)/sizeof(func[0]);
        decstr(func,lfunc);

        decode(base, func);
    }

}


