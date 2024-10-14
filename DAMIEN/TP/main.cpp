#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <stdarg.h>

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

// Fonction pour recharger ntdll.dll
void ReloadNtdll() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == nullptr) {
        std::cerr << "Impossible de charger ntdll.dll" << std::endl;
        exit(1);
    }
}

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

#else // Linux
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <sys/wait.h>

void ReloadNtdll() {
    // Sur Linux, il n'y a pas de rechargement de bibliothèque comme sur Windows
    std::cout << "Pas de rechargement de bibliothèque requis sur Linux." << std::endl;
}

extern "C" int SysOpenProcess(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Échec de l'attachement au processus : " << strerror(errno) << std::endl;
        return -1;
    }

    // Attendre que le processus soit stoppé
    waitpid(pid, nullptr, 0);

    std::cout << "Processus attaché avec succès !" << std::endl;

    // Détacher le processus
    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Échec du détachement du processus : " << strerror(errno) << std::endl;
        return -1;
    }

    std::cout << "Processus détaché avec succès !" << std::endl;
    return 0;
}
#endif

int main() {
    // Remplacez 1234 par le PID de votre choix
#ifdef _WIN32
    ReloadNtdll();
    HANDLE hProcess = nullptr;
    CLIENT_ID clientId = { (HANDLE)1234, nullptr }; // PID ici
    OBJECT_ATTRIBUTES objAttr = { 0 };

    NTSTATUS status = NtOpenProcessSyscall(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != 0) {
        std::cerr << "Échec de l'ouverture du processus avec syscall : " << status << std::endl;
        return 1;
    }
    std::cout << "Processus ouvert avec succès via syscall !" << std::endl;
    CloseHandle(hProcess);
#else // Linux
    pid_t pid = 861; // Remplacez par le PID de votre choix
    if (SysOpenProcess(pid) == -1) {
        return 1;
    }
#endif

    return 0;
}
