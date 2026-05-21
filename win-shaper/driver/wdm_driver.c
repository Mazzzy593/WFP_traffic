/*
Copyright 2016 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "common.h"

/*-----------------------------------------------------------------------------
  GUIDs
-----------------------------------------------------------------------------*/

// c9ea094d-b304-4f7c-bfc6-608b0ecc5447
DEFINE_GUID(
    SHAPER_OUTBOUND_CALLOUT,
    0xc9ea094d,
    0xb304,
    0x4f7c,
    0xbf, 0xc6, 0x60, 0x8b, 0x0e, 0xcc, 0x54, 0x47
);
// 4fbb02a9-0e93-471e-a04c-d1439b5d402e
DEFINE_GUID(
    SHAPER_INBOUND_CALLOUT,
    0x4fbb02a9,
    0x0e93,
    0x471e,
    0xa0, 0x4c, 0xd1, 0x43, 0x9b, 0x5d, 0x40, 0x2e
);
// ac63c367-b14f-483a-89fc-196c98eec1ad
DEFINE_GUID(
    SHAPER_SUBLAYER,
    0xac63c367,
    0xb14f,
    0x483a,
    0x89, 0xfc, 0x19, 0x6c, 0x98, 0xee, 0xc1, 0xad
);
DEFINE_GUID(
    SHAPER_IP_OUTBOUND_CALLOUT,
    0xb92a091d,
    0x6304,
    0x4a7c,
    0xbe, 0xc6, 0x60, 0x7b, 0x0e, 0x2c, 0x54, 0x47
);
DEFINE_GUID(
    SHAPER_IP_INBOUND_CALLOUT,
    0x5d6a094d,
    0xb364,
    0x437c,
    0x09, 0xc6, 0x22, 0x8b, 0x0e, 0xcc, 0x54, 0x47
);
/*-----------------------------------------------------------------------------
  Globals
-----------------------------------------------------------------------------*/
DEVICE_OBJECT* wdm_device = NULL;
BOOLEAN driver_unloading = FALSE;
HANDLE engine_handle = NULL;
UINT32 outbound_callout_id = 0, inbound_callout_id = 0;
UINT32 outbound_IP_callout_id = 0, inbound_IP_callout_id = 0;
// packet injection handles for inbound/outbound IPv4/IPv6/Unspecified
HANDLE ih_out_ipv4 = NULL;
HANDLE ih_out_ipv6 = NULL;
HANDLE ih_out_unspecified = NULL;
HANDLE ih_in_ipv4 = NULL;
HANDLE ih_in_ipv6 = NULL;
HANDLE ih_in_unspecified = NULL;

/*-----------------------------------------------------------------------------
  Forward declarations
-----------------------------------------------------------------------------*/
NTSTATUS ShaperInitDriverObjects(
    _Inout_ DRIVER_OBJECT* driverObject,
    _In_ const UNICODE_STRING* registryPath,
    _Out_ WDFDRIVER* pDriver,
    _Out_ WDFDEVICE* pDevice);
NTSTATUS RegisterCallouts(_Inout_ void* deviceObject);
void Cleanup(void);
NTSTATUS WaitForWFP();

/******************************************************************************
******************************************************************************/
