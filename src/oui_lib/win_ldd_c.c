
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/callback.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#if defined(_WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#define TRACE(fmt, ...) \
  do { \
    fprintf(stderr, "Win ldd: " fmt "\n", ##__VA_ARGS__); \
    fflush(NULL); \
  } while(0)

static const size_t BUFFER_SIZE = 1024;

static void raise_error(const char *restrict fmt, ...) {
  CAMLparam0();
  va_list args;
  va_start(args, fmt);
  char buff[BUFFER_SIZE] = {};
  vsnprintf(buff, BUFFER_SIZE, fmt, args);
  caml_raise_with_string(*caml_named_value("Win_ldd.Error"), buff);
}

value ml_wchar_to_value(const WCHAR *string, UINT codepage)
{
  CAMLparam0();
  CAMLlocal1(mlResult);
  int w_len = wcslen(string);
  int len = WideCharToMultiByte(CP_UTF8, 0, string, w_len, NULL, 0, NULL, NULL);
  if (len == 0) {
    mlResult = caml_copy_string("");
  } else {
    mlResult = caml_alloc_string(len);
    WideCharToMultiByte(CP_UTF8, 0, string, w_len, (char *)Bytes_val(mlResult), len, NULL, NULL);
  }
  CAMLreturn(mlResult);
}

WCHAR * ml_value_to_wchar(value mlString, UINT codepage)
{
  CAMLparam1(mlString);
  WCHAR *result = NULL;
  int w_len = MultiByteToWideChar(codepage, 0, String_val(mlString), -1, NULL, 0);
  if (w_len == 0) {
    result = NULL;
  } else {
    result = (WCHAR *)malloc(w_len * sizeof(WCHAR));
    if (result != NULL) {
      MultiByteToWideChar(codepage, 0, String_val(mlString), -1, result, w_len);
    }
  }
  CAMLreturnT(WCHAR *, result);
}

#define Val_HMODULE(x) Val_long((HMODULE)x)
#define HMODULE_Val(x) (HMODULE)Long_val(x)

static value ml_get_module_filename(HANDLE hp, HMODULE hm) {
  CAMLparam0();
  CAMLlocal1(mlResult);

  size_t len = 0;
  DWORD res;
  WCHAR* buf = NULL;

  do {
    len += 1024;
    buf = realloc(buf, len * sizeof(*buf));
    res = GetModuleFileNameExW(hp, hm, buf, len);
    if (res == 0)
      goto failure;
  } while (res == len);

  TRACE("found %ls at %p", buf, hm);
  mlResult = ml_wchar_to_value(buf, CP_UTF8);
  free(buf);
  CAMLreturn(mlResult);

failure:
  free(buf);
  raise_error("cannot retrieve the filename of the module \
    with Last-Error code %ld", GetLastError());
}

static value ml_get_module_filenames(HANDLE hp, value mlList) {
  CAMLparam1(mlList);
  CAMLlocal2(mlCurr, mlCell);
  mlCurr = Val_emptylist;

  while(!Is_long(mlList)) {
    HMODULE hm = HMODULE_Val(Field(mlList, 0));
    mlCell= caml_alloc(2, 0);
    Field(mlCell, 0) = ml_get_module_filename(hp, hm);
    Field(mlCell, 1) = mlCurr;
    mlCurr = mlCell;
    mlList = Field(mlList, 1);
  }

  CAMLreturn(mlCurr);
}

static const size_t DOS_HEADER_SIZE = 4096;

static PVOID process_entry_point(HANDLE hProcess, LPVOID lpBaseOfImage) {
  PIMAGE_DOS_HEADER dos_header = alloca(DOS_HEADER_SIZE);
  ReadProcessMemory(hProcess, lpBaseOfImage, dos_header, DOS_HEADER_SIZE, NULL);
  PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS) ((PBYTE)dos_header + dos_header->e_lfanew);
  return lpBaseOfImage + nt_header->OptionalHeader.AddressOfEntryPoint;
}

static const unsigned char int3 = 0xcc;

#define HANDLE_Val(x) (HANDLE)Long_val(x)
#define Val_HANDLE(x) Val_long((HANDLE)x)
#define DWORD_Val(x) (DWORD)Int_val(x)
#define Val_DWORD(x) Val_int((DWORD)x)

static value Val_debugger(HANDLE process, DWORD processId, DWORD threadId) {
  CAMLparam0();
  CAMLlocal(mlRes);
  mlRes = caml_alloc(3, 0);
  Field(mlRes, 0) = Val_HANDLE(process);
  Field(mlRes, 1) = Val_DWORD(processId);
  Field(mlRes, 2) = Val_DWORD(threadId);
  CAMLreturn(mlRes);
}

#define Process_Val(x) HANDLE_Val(Field(x, 0))
#define ProcessId_Val(x) DWORD_Val(Field(x, 1))
#define ThreadId_val(x) DWORD_Val(Field(x, 2))

CAMLprim value ml_start_debugger(value mlPath) {
  CAMLparam1(mlPath);
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  WCHAR* path = ml_value_to_wchar(mlPath, CP_UTF8);
  if(!CreateProcessW(NULL, path, NULL, NULL, FALSE,
      DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
    raise_error("cannot start the process");

  HANDLE process = pi.hProcess;
  DWORD processId = GetProcessId(process);
  DWORD threadId = GetThreadId(process);
  CAMLreturn(Val_debugger(process, processId, threadId));
}

static void wait_for_debug_event(value mlDebugger, DEBUG_EVENT *ev) {
  CAMLparam1(mlDebugger);
  WaitForDebugEvent(ev, INFINITE);
  Field(mlDebugger, 1) = Val_DWORD(ev->dwProcessId);
  Field(mlDebugger, 2) = Val_DWORD(ev->dwThreadId);
  CAMLreturn0();
}

static void continue_debugger(value mlDebugger) {
  CAMLparam1(mlDebugger);
  ContinueDebugEvent(ProcessId_Val(mlDebugger), ThreadId_Val(mlDebugger), DBG_CONTINUE);
  CAMLreturn0();
}

CAMLprim value ml_stop_debugger(value mlDebugger) {
  CAMLparam1(mlDebugger);
  HANDLE process = Process_Val(mlDebugger);
  DEBUG_EVENT ev;

  while (1) {
    wait_for_debug_event(mlDebugger, &ev);

    switch (ev.dwDebugEventCode) {
      case EXIT_PROCESS_DEBUG_EVENT:
        TRACE("exit process");
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        WaitForSingleObject(process, INFINITE);
        CloseHandle(process);
        CAMLreturn(Val_unit);
    }

    continue_debugger(mlDebugger);
  }
}

CAMLprim value ml_wait_dll_event(value mlDebugger) {
  CAMLparam1(mlDebugger);
  CAMLlocal1(res);
  HANDLE process = HANDLE_Val(mlProcess);
  DEBUG_EVENT ev;
  BOOL cont = TRUE;

  while (cont) {
    wait_for_debug_event(mlDebugger, &ev);

    switch (ev.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT:
        TRACE("process created");
        PVOID entry_point =
          process_entry_point(process, ev.u.CreateProcessInfo.lpBaseOfImage);
        WriteProcessMemory(process, entry_point, &int3, sizeof(int3), NULL);
        break;

      case LOAD_DLL_DEBUG_EVENT:
        TRACE("load dll at 0x%p", ev.u.LoadDll.lpBaseOfDll);
        res = caml_alloc(1, 0);
        Field(res, 0) = Val_long(ev.u.LoadDll.lpBaseOfDll);
        cont = FALSE;
        break;

      case UNLOAD_DLL_DEBUG_EVENT:
        TRACE("unload dll at 0x%p", ev.u.UnloadDll.lpBaseOfDll);
        res = caml_alloc(1, 1);
        Field(res, 0) = Val_long(ev.u.UnloadDll.lpBaseOfDll);
        cont = FALSE;
        break;

      case EXCEPTION_DEBUG_EVENT:
        switch (ev.u.Exception.ExceptionRecord.ExceptionCode) {
          case STATUS_BREAKPOINT:
            TRACE("reached the entrypoint of the program");
            TerminateProcess(process, 0);
            CAMLreturn(Val_none);
        }
        break;
    }

    continue_debugger(mlDebugger);
  }

  CAMLreturn(caml_alloc_some(res));
}

CAMLprim value ml_get_dll_filename(value mlProcess, value mlAddr) {
  CAMLparam2(mlProcess, mlAddr);
  CAMLlocal1(mlRes);
  HANDLE process = HANDLE_Val(mlProcess);
  HMODULE addr = HMODULE_Val(mlAddr);

  size_t len = 0;
  DWORD res;
  WCHAR* buf = NULL;

  do {
    len += 1024;
    buf = realloc(buf, len * sizeof(*buf));
    res = GetModuleFileNameExW(process, addr, buf, len);
    if (res == 0)
      goto failure;
  } while (res == len);

  TRACE("found %ls at %p", buf, addr);
  mlRes = ml_wchar_to_value(buf, CP_UTF8);
  free(buf);
  CAMLreturn(mlRes);

failure:
  free(buf);
  raise_error("cannot retrieve the filename of the module \
    with Last-Error code %ld", GetLastError());
}

CAMLprim value ml_get_windows_directory(value mlUnit)
{
  CAMLparam1(mlUnit);
  CAMLlocal1(mlResult);
  WCHAR path[MAX_PATH+1];
  UINT len = GetWindowsDirectoryW(path, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) {
    caml_failwith("GetWindowsDirectoryW failed");
  }
  if (path[len - 1] != L'\\') {
    path[len++] = L'\\';
    path[len] = L'\0';
  }
  mlResult = ml_wchar_to_value(path, CP_UTF8);
  CAMLreturn(mlResult);
}

#else

CAMLprim value ml_get_windows_directory(value mlUnit)
{
  CAMLparam1(mlUnit);
  CAMLreturn(caml_copy_string(""));
}

#endif
