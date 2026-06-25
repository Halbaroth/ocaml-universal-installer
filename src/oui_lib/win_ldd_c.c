
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
    vfprintf(stderr, "Win ldd: " fmt "\n", ##__VA_ARGS__); \
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
    if (res == 0) {
      free(buf);
      // raise_error("cannot retrieve the filename of the module with last error %ld", GetLastError());
      TRACE("cannot retrieve the filename of the module with last error %ld", GetLastError());
      mlResult = caml_copy_string("");
    }
  } while (res == len);

  TRACE("found %ls at %p", buf, hm);
  mlResult = ml_wchar_to_value(buf, CP_UTF8);
  free(buf);
  CAMLreturn(mlResult);
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

static HANDLE ml_start_process(value mlPath) {
  raise_error("PLOP");
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

  CAMLreturnT(HANDLE, pi.hProcess);
}

CAMLprim value ml_report_dlls(value mlPath) {
  CAMLparam1(mlPath);
  CAMLlocal3(mlCurr, mlCell, mlResult);
  HANDLE hProcess = ml_start_process(mlPath);
  DEBUG_EVENT ev;
  mlCurr = Val_emptylist;
  mlResult = Val_emptylist;

  while (1) {
    if (!WaitForDebugEvent(&ev, INFINITE))
      raise_error("Failed to wait for the next debug event with last-error code %ld", GetLastError());

    switch (ev.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT:
        TRACE("process created");
        PVOID entry_point =
          process_entry_point(hProcess, ev.u.CreateProcessInfo.lpBaseOfImage);
        WriteProcessMemory(hProcess, entry_point, &int3, sizeof(int3), NULL);
        break;

      case LOAD_DLL_DEBUG_EVENT:
        TRACE("loading dll at 0x%p", ev.u.LoadDll.lpBaseOfDll);
        HMODULE hm = ev.u.LoadDll.lpBaseOfDll;
        mlCell = caml_alloc(2, 0);
        Field(mlCell, 0) = Val_HMODULE(hm);
        Field(mlCell, 1) = mlCurr;
        mlCurr = mlCell;
        break;

      case EXCEPTION_DEBUG_EVENT:
        switch (ev.u.Exception.ExceptionRecord.ExceptionCode) {
          case STATUS_BREAKPOINT:
            TRACE("reached the entrypoint of the program");
            mlResult = ml_get_module_filenames(hProcess, mlCurr);
            TerminateProcess(hProcess, 0);
            break;
        }
        break;

      case UNLOAD_DLL_DEBUG_EVENT:
        TRACE("unloading dll at 0x%p", ev.u.UnloadDll.lpBaseOfDll);
        break;

      case EXIT_PROCESS_DEBUG_EVENT:
        TRACE("exit process");
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        WaitForSingleObject(hProcess, INFINITE);
        CAMLreturn(mlResult);
    }

    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
  }
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

CAMLprim value ml_report_dlls(value mlPath)
{
  CAMLparam1(mlPath);
  CAMLreturn(Val_emptylist);
}

CAMLprim value ml_get_windows_directory(value mlUnit)
{
  CAMLparam1(mlUnit);
  CAMLreturn(caml_copy_string(""));
}

#endif
