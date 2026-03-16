#pragma once



#include <Ntifs.h>
#include <wdf.h>




#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union




#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>




#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>




#define INITGUID
#include <guiddef.h>



#include "interface.h"
#include "wfp_callout.h"
#include "packet_queue.h"




// new code
#include "ipfragment.h"
#include "IP_callout.h"
#include "protocol-headers.h"

//#ifndef DEBUG
//#define DEBUG 1
//#endif // !DEBUG


//#define NOGUI 1

