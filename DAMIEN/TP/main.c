#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>

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
    if (ntdll == NULL) {
        fprintf(stderr, "Impossible de charger ntdll.dll\n");
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
#include <string.h>
#include <sys/wait.h>
#include <errno.h>

void ReloadNtdll() {
    // Sur Linux, il n'y a pas de rechargement de bibliothèque comme sur Windows
    printf("Pas de rechargement de bibliothèque requis sur Linux.\n");
}

int SysOpenProcess(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Échec de l'attachement au processus : %s\n", strerror(errno));
        return -1;
    }

    // Attendre que le processus soit stoppé
    waitpid(pid, NULL, 0);

    printf("Processus attaché avec succès !\n");

    // Détacher le processus
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Échec du détachement du processus : %s\n", strerror(errno));
        return -1;
    }

    printf("Processus détaché avec succès !\n");
    return 0;
}
#endif

int main() {
    // Remplacez 1234 par le PID de votre choix
#ifdef _WIN32
    ReloadNtdll();
    HANDLE hProcess = NULL;
    CLIENT_ID clientId = { (HANDLE)1234, NULL }; // PID ici
    OBJECT_ATTRIBUTES objAttr = { 0 };

    NTSTATUS status = NtOpenProcessSyscall(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != 0) {
        fprintf(stderr, "Échec de l'ouverture du processus avec syscall : %x\n", status);
        return 1;
    }
    printf("Processus ouvert avec succès via syscall !\n");
    CloseHandle(hProcess);
#else // Linux
    pid_t pid = 861; // Remplacez par le PID de votre choix
    if (SysOpenProcess(pid) == -1) {
        return 1;
    }
#endif

    return 0;
}
