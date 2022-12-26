#include <elf.h>
#include <memory>
#include <vector>

namespace zhook {

typedef struct {
    unsigned long e_shoff;
    unsigned int e_shentsize;
    unsigned int e_shnum;
} Elf_Ehdr;

typedef struct {
    unsigned int sh_type;
    unsigned long sh_offset;
    unsigned long sh_size;
    unsigned int sh_link;
    unsigned long sh_entsize;
} Elf_Shdr;

typedef struct {
    char* name;
    unsigned char bind;
    unsigned char type;
    unsigned short shndx;
    unsigned long value;
    unsigned long size;
} Elf_SymbolSection;

typedef struct {
    unsigned long offset;
    unsigned long type;
    unsigned long symid;
} Elf_RealSymbolSection;

class ELFManager {
public:
    ~ELFManager();
    ELFManager(const ELFManager&) = delete;
    ELFManager& operator=(const ELFManager&) = delete;
    ELFManager(ELFManager&&) = delete;
    ELFManager& operator=(ELFManager&&) = delete;

    static ELFManager& get_instance() {
        static ELFManager obj;
        return obj;
    }

    int init(const char* file_name);
    int get_elf_symtab(std::shared_ptr<std::vector<Elf_SymbolSection>> symtab);


private:
    ELFManager() = default;

    int read_elf_symbol_section(std::shared_ptr<std::vector<Elf_SymbolSection>> symtab, unsigned int type);

    int read_elf_relsym_section(std::shared_ptr<std::vector<Elf_RealSymbolSection>> rel_table, unsigned max_count);

    /**
     * @brief 读取 ELF 文件的文件头
     * 
     * @param ehdr ELF 文件头的结构体
     * @return int 是否成功，0 为成功，非 0 为失败
     */
    int read_elf_ehdr();

    /**
     * @brief 获取 ELF 文件的段表
     * 
     * @param shdrs ELF 文件的段表结构体
     * @param shnum 段的个数
     * @return int 是否成功，0 为成功，非 0 为失败
     */
    int read_elf_shdrs(unsigned int shnum);

    /**
     * @brief 辅助函数，读取 ELF 文件
     * 
     * @param pos 文件偏移
     * @param buf 缓冲区
     * @param count 读取大小
     * @return int 是否成功，0 为成功，非 0 为失败
     */
    int read_elf(int pos, void* buf, int count);

private:
    int fd_;  // 文件描述符
    char ident_[EI_NIDENT] = {0};  // ELF 文件头的 ident 字段
    bool is_32_bit_ = false;  // 是否为 32 位的 ELF 文件
    Elf_Ehdr ehdr_{0};  // ELF 文件头
    std::vector<Elf_Shdr> shdrs_;  // ELF 文件段表数组
};

}  // namespace zhook
