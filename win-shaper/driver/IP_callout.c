#include "common.h"

#define IPH_TCP 0x06
#define TCPCALLOUT_POOL_TAG 'tcpT'
// GLOBALS
//extern HANDLE tcp_ih_out;
//extern HANDLE tcp_ih_in;
extern BOOLEAN driver_unloading;
extern HANDLE ipv4_injectionhandle_out;
extern HANDLE ipv4_injectionhandle_in;

extern UINT SELF_MTUmin;
extern UINT SELF_MTUmax;
extern BOOLEAN TCPFragment_enable;

//LOCAL
BOOLEAN Debugflags = TRUE;

//
// IP Packet
// PENDED_IP_PACKET_
typedef struct TL_INSPECT_PENDED_PACKET_
{
	LIST_ENTRY listEntry;
	FWP_DIRECTION direction;
	NET_BUFFER_LIST* netBufferList;

	UINT32 ipHeaderSize;
	COMPARTMENT_ID compartmentId;
	IF_INDEX interfaceIndex;
	IF_INDEX subInterfaceIndex;

} TL_INSPECT_PENDED_PACKET;


void IPClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues, //contains fixed information about the incoming packet, such as the layer ID, source and destination addresses
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues, //metadata information about the packet, such as the interface index, timestamps
	_Inout_opt_ void* layerData, //a pointer to layer-specific data that is associated with the packet
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter, //a pointer to the filter that matched the packet
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut) 
{

	NT_ASSERT(filter);
	NT_ASSERT(classifyOut);  
	UNREFERENCED_PARAMETER(classifyContext); 
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(inMetaValues);


	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) { 
		NT_ASSERT(layerData != NULL);  
		_Analysis_assume_(layerData != NULL);

		HANDLE injection_handle = NULL;
		BOOLEAN is_outbound = (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4);
		BOOLEAN fragmented = FALSE;

		injection_handle = ipv4_injectionhandle_out;

		// 对于inbound的流量，可能不需要检查是否重注入
		FWPS_PACKET_INJECTION_STATE packet_state = FwpsQueryPacketInjectionState(injection_handle, layerData, NULL);

		if (!driver_unloading &&  // driver is not unloading
			classifyOut->actionType != FWP_ACTION_BLOCK && 
			(packet_state != FWPS_PACKET_INJECTED_BY_SELF) &&
			(packet_state != FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)) 
		{
			if(is_outbound && TCPFragment_enable)
				fragmented = TCPandIPfragment(inFixedValues, inMetaValues, layerData, is_outbound, injection_handle);
		}


		if (fragmented) {
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		}
		else {
			classifyOut->actionType = FWP_ACTION_PERMIT;
			if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
				classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}
	}
	return;

}



__drv_allocatesMem(Mem)
TL_INSPECT_PENDED_PACKET*
AllocateAndInitializePendedPacket(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData
)
{
	TL_INSPECT_PENDED_PACKET* pendedPacket = ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(TL_INSPECT_PENDED_PACKET),
		TCPCALLOUT_POOL_TAG
	);

	if (pendedPacket == NULL)
		return NULL;

	RtlZeroMemory(pendedPacket, sizeof(TL_INSPECT_PENDED_PACKET));

	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4) {
		pendedPacket->direction = FWP_DIRECTION_OUTBOUND;
	}
	else {
		pendedPacket->direction = FWP_DIRECTION_INBOUND;
	}

	if (layerData != NULL)
	{
		pendedPacket->netBufferList = layerData;
	}

	NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_COMPARTMENT_ID));
	pendedPacket->compartmentId = inMetaValues->compartmentId;

	if (pendedPacket->direction == FWP_DIRECTION_OUTBOUND)
	{
	}
	else
	{
		pendedPacket->interfaceIndex =
			inFixedValues->incomingValue[
				FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
		pendedPacket->subInterfaceIndex =
			inFixedValues->incomingValue[
				FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

		NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
			FWPS_METADATA_FIELD_IP_HEADER_SIZE));
		pendedPacket->ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	return pendedPacket;
}




NTSTATUS
AllocateCloneNetBufferList(
	_Inout_ NET_BUFFER_LIST* netBufferList,
	_In_ UINT32 bytesRetreated,
	_Outptr_ NET_BUFFER_LIST** clonedNetBufferList
)
{

	NTSTATUS status = STATUS_SUCCESS;
	//
	// Note that the clone will inherit the original net buffer list's offset.
	//

	if (bytesRetreated)

		NdisRetreatNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(netBufferList), bytesRetreated, 0, NULL);

	status = FwpsAllocateCloneNetBufferList(
		netBufferList,
		NULL,
		NULL,
		0,
		clonedNetBufferList
	);
	if (bytesRetreated)
		
		NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(netBufferList), bytesRetreated, FALSE, NULL);

	return status;
}

//LOCAL function
VOID IPfragementFree(PNET_BUFFER_LIST netBufferList)
{
	FwpsFreeNetBufferList(netBufferList);
	netBufferList = NULL;
}

void IPInjectionComplete(_Inout_ void* context,
	_Inout_ PNET_BUFFER_LIST netBufferList,
	_In_ BOOLEAN dispatchLevel) 
{
	UNREFERENCED_PARAMETER(dispatchLevel);

	if (!NT_SUCCESS(netBufferList->Status))
	{
		DbgPrint("! Packet injection failed: 0x%08X\n", netBufferList->Status);
	}

	IPfragementFree(netBufferList);
	if (context != NULL) {
		ExFreePoolWithTag((TL_INSPECT_PENDED_PACKET*)context, TCPCALLOUT_POOL_TAG);
		context = NULL;
	}
}




