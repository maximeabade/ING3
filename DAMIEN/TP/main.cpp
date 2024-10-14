#include <windows.h>
#include <iostream>

extern "C" NTSTATUS NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

typedef NTSTATUS(*NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

NtOpenProcess_t OriginalNtOpenProcess = nullptr;

// Fonction qui recharge ntdll.dll depuis le disque
void ReloadNtdll() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == nullptr) {
        std::cerr << "Impossible de charger ntdll.dll" << std::endl;
        exit(1);
    }
    OriginalNtOpenProcess = (NtOpenProcess_t)GetProcAddress(ntdll, "NtOpenProcess");
    if (OriginalNtOpenProcess == nullptr) {
        std::cerr << "Impossible de localiser NtOpenProcess" << std::endl;
        exit(1);
    }
}

// Utilisation de l'assembleur pour faire un syscall
extern "C" NTSTATUS NtOpenProcessSyscall(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {

    __asm {
        mov eax, 0x23   // Numéro de syscall pour NtOpenProcess
        mov edx, [esp + 4]  // ProcessHandle
        mov ecx, [esp + 8]  // DesiredAccess
        mov ebx, [esp + 12] // ObjectAttributes
        mov esi, [esp + 16] // ClientId
        int 0x2e           // Interruption système
    }
}

int main() {
    // Recharger ntdll
    ReloadNtdll();

    // PID du processus à ouvrir
    DWORD pid = 1234;
    HANDLE hProcess = nullptr;
    CLIENT_ID clientId = { (HANDLE)pid, nullptr };
    OBJECT_ATTRIBUTES objAttr = { 0 };

    NTSTATUS status = NtOpenProcessSyscall(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);

    if (status != 0) {
        std::cerr << "Échec de l'ouverture du processus avec syscall : " << status << std::endl;
        return 1;
    }

    std::cout << "Processus ouvert avec succès via syscall !" << std::endl;

    // Fermer le handle du processus
    CloseHandle(hProcess);

    return 0;
}
