// exe.cpp : Defines the entry point for the console application.
//

#include "targetver.h"
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <Shlwapi.h>

#include "../driver/interface.h"

bool Start() {
  bool ok = false;
  SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); 
  if (scm) {
    SC_HANDLE service = OpenService(scm, SHAPER_SERVICE_NAME, SERVICE_ALL_ACCESS); 
    if (service) {
      DWORD dwBytesNeeded;
      SERVICE_STATUS_PROCESS status;
      if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
          if (StartService(service, 0, NULL)) {
            DWORD count = 0;
            do {
              QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded);
              if (status.dwCurrentState == SERVICE_START_PENDING)
                Sleep(100);
              count++;
            } while(status.dwCurrentState == SERVICE_START_PENDING && count < 600);
            if (status.dwCurrentState == SERVICE_RUNNING) {
              ok = true;
            } else {
              printf("Error waiting for service to start\n");
            }
          } else {
            printf("Failed to start the service\n");
          }
        } else {
          ok = true;
        }
      } else {
        printf("Failed to query the current service status\n");
      }
      CloseServiceHandle(service);
    } else {
      printf("Failed to open the shaper service\n");
    }
    CloseServiceHandle(scm);
  } else {
    printf("Failed to open the Service Control Manager\n");
  }
  return ok;
}

bool Install() {
  bool ok = false;
  SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); 
  if (scm) {
    SC_HANDLE service = OpenService(scm, SHAPER_SERVICE_NAME, SERVICE_ALL_ACCESS); 
    if (!service) {
      TCHAR driver_path[MAX_PATH];
      GetModuleFileName(NULL, driver_path, MAX_PATH);
      BOOL is64bit = FALSE;
      IsWow64Process(GetCurrentProcess(), &is64bit);
      if (is64bit)
        lstrcpy(PathFindFileName(driver_path), _T("shaper64.sys"));
      else
        lstrcpy(PathFindFileName(driver_path), _T("shaper32.sys"));
      service = CreateService(scm,
                              SHAPER_SERVICE_NAME,
                              SHAPER_SERVICE_DISPLAY_NAME,
                              SERVICE_ALL_ACCESS,
                              SERVICE_KERNEL_DRIVER,
                              SERVICE_DEMAND_START,
                              SERVICE_ERROR_NORMAL,
                              driver_path,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
      if (service) {
        CloseServiceHandle(service);
        ok = Start();
      } else {
        printf("Failed to install shaper driver\n");
      }
    } else {
      CloseServiceHandle(service);
      ok = Start();
    }
    CloseServiceHandle(scm);
  } else {
    printf("Failed to open the Service Control Manager\n");
  }
  return ok;
}
