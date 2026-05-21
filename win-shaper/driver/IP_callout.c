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

		// ����inbound�����������ܲ���Ҫ����Ƿ���ע��
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


/* Checksum a block of data */
UINT16 csum(UINT16* packet, int packlen) {

	register UINT32 sum = 0;

	while (packlen > 1) {
		sum += *(packet++);
		packlen -= 2;
	}

	if (packlen > 0)
		sum += *(PUCHAR)packet;

	/* TODO: this depends on byte order */

	while (sum >> 16)

		sum = (sum & 0xffff) + (sum >> 16);

	return (UINT16)~sum;
}


void updateTCPchecksum(PUCHAR pIPHeader, PUCHAR pTCPHeader, PUCHAR pPayload, UINT TCPHeaderLen, UINT PayloadLen)
{
	UNREFERENCED_PARAMETER(pPayload);

	TCP_HEADER* tcp = (TCP_HEADER*)pTCPHeader;

	UINT16* buf = ExAllocatePoolWithTag(NonPagedPool,12 + TCPHeaderLen + PayloadLen,TCPCALLOUT_POOL_TAG);
	if (buf == NULL)
		return;

	UCHAR* tempbuf = (UCHAR*)buf;

	tcp->checksum = 0;

	/* ����αͷ�� */

	memcpy(tempbuf, pIPHeader + 12, 4);
	memcpy(tempbuf+4, pIPHeader + 16, 4);

	tempbuf[8] = 0;
	tempbuf[9] = 0x06;


	UINT16 tmpLen = TCPHeaderLen + PayloadLen;
	tempbuf[10] = (UINT16)(tmpLen & 0xFF00) >> 8;
	tempbuf[11] = (UINT16)(tmpLen & 0x00FF);

	/* Copy the TCP header and data */
	memcpy(tempbuf + 12, pTCPHeader, TCPHeaderLen + PayloadLen);

	/* CheckSum it */
	tcp->checksum = csum(buf, 12 + TCPHeaderLen + PayloadLen);

	ExFreePoolWithTag(buf,TCPCALLOUT_POOL_TAG);
}


VOID updateTCPSeqNumber(PUCHAR tcpPacket,UINT alreadyCopied)
{
	PUCHAR pSeqNumber = tcpPacket + 4;
	UINT currentSeqNumber = (UINT)(pSeqNumber[0] << 24 | pSeqNumber[1] << 16 | pSeqNumber[2] << 8 | pSeqNumber[3]);

	currentSeqNumber += alreadyCopied;
	PUCHAR tmp = (PUCHAR)&currentSeqNumber;

	pSeqNumber[0] = tmp[3];
	pSeqNumber[1] = tmp[2];
	pSeqNumber[2] = tmp[1];
	pSeqNumber[3] = tmp[0];
}

BOOLEAN TCPandIPfragment(_In_ const FWPS_INCOMING_VALUES* inFixedValues,   // ������װ�����ݰ��������Ϣ�� ��layer ID, source and destination addresses
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,   // ������װ��������Ϣ��interface index, timestamps
	_Inout_opt_ void* layerData,
	BOOLEAN outbound, // ��־λ
	_In_ HANDLE injection_handle) 
{
#ifdef DEBUG
	if (Debugflags)
	{
		DbgBreakPoint();
		Debugflags = FALSE;
	}
#endif
	NTSTATUS status;
	
	LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
	ULONG random = RtlRandomEx(&now.LowPart) % 100;
	if (random > SELF_TCPFragmentRate)
		return FALSE;

	ULONG randomMSS = SELF_MSSmin + RtlRandomEx(&now.LowPart) % ((SELF_MSSmax - SELF_MSSmin)>0? (SELF_MSSmax - SELF_MSSmin):1);

	PNET_BUFFER_LIST CopyLayerdata = NULL;
	TL_INSPECT_PENDED_PACKET* pendedPacket = NULL;
	PIPV4_HEADER ipHeaderInfo = NULL;
	pendedPacket = AllocateAndInitializePendedPacket(
		inFixedValues,
		inMetaValues,
		layerData
	);

	// ����IP��TCP��ͷ
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);
	PNET_BUFFER currentNB = NULL;	// �����currentNB��ָ��ǰ��������NET_BUFFER_LIST�����һ��NET_BUFFER

	PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
	PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);
	ipHeaderInfo = (PIPV4_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPV4_HEADER), TCPCALLOUT_POOL_TAG);
	IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData);		

	// 1. �ж�Э������
	if (ipHeaderInfo->Protocol != IPH_TCP) {
		goto EXIT;
	}
	// 2. �ж����ݰ������Ƿ���Ҫ��Ƭ	
	if (ipHeaderInfo->TotalLength < SELF_MSSmax) {
		goto EXIT;
	}
	UINT16 IPHeaderLen = ipHeaderInfo->HeaderLength;

	NdisAdvanceNetBufferDataStart(nb, IPHeaderLen, 0, 0);
	PTCP_HEADER pTCPHeader = NdisGetDataBuffer(nb, sizeof(TCP_HEADER), NULL, 1, 0);
	NdisRetreatNetBufferDataStart(nb, IPHeaderLen, 0, 0);
	UINT TCPHeaderLen = pTCPHeader->dORNS.dataOffset * 4;

	///////////////////////////////////////////////////////////////////////////////////////////
	//  TCPfragement
	///////////////////////////////////////////////////////////////////////////////////////////
	// 
	// ��Ƭ�õ��Ĳ�����
	
	ULONG payloadLen = ipHeaderInfo->TotalLength - IPHeaderLen - TCPHeaderLen;
	ULONG remainDataLen = payloadLen;	// ʣ���ֽڳ���
	UINT32 currentSeqNum = pTCPHeader->sequenceNumber;
	
	CopyLayerdata = (PNET_BUFFER_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(NET_BUFFER_LIST), TCPCALLOUT_POOL_TAG);

	//����һ����NBL������NB��NB�в�û��MDL
	FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, NULL, 0, 0, &CopyLayerdata);
	currentNB = NET_BUFFER_LIST_FIRST_NB(CopyLayerdata);
	
	

	UINT TCPIPHeadersLen = IPHeaderLen + TCPHeaderLen;
	ULONG MSSandTCPIPHeader = randomMSS + TCPIPHeadersLen;
	ULONG currentMDLSize = MSSandTCPIPHeader;

	if (ipHeaderInfo->Flags == 1 || ipHeaderInfo->FragmentOffset > 0)
		goto EXIT; 

	UCHAR ipFlags = 0;
	if (ipHeaderInfo->Flags == 2)
		ipFlags = 0b01000000;

	// NdisCopyFromNetBufferToNetBuffer����Ҫ�õĲ�������
	ULONG bytestocopy = 0;
	ULONG bytescopied = 0;
	ULONG DestionationOffset = 0;
	ULONG SourceOffset = 0;

	while (remainDataLen) {
		
		if (remainDataLen != payloadLen)
		{	// ��ʱ���ǵ�һ�ν���ѭ�����ȷ����µ�NB
			PNET_BUFFER newNB = NdisAllocateNetBuffer(nbPoolHandle_datasize0, NULL, 0, 0);
			NET_BUFFER_NEXT_NB(currentNB) = newNB;
			currentNB = newNB;
		}
		// �ȸ���ǰNB����һ���㹻���MDL
		currentMDLSize = remainDataLen > randomMSS ? MSSandTCPIPHeader : (remainDataLen + TCPIPHeadersLen);

		if (currentMDLSize > 0) {
			status = NdisRetreatNetBufferDataStart(currentNB,currentMDLSize,0,NULL);
			if (!NT_SUCCESS(status))
				goto EXIT;
		}
		// ������MDL�� Ҫ���п�������һƬ�Ŀ���ֱ�Ӵ�IPͷ��ʼ
		if (remainDataLen == payloadLen)	// remainDataLen����ԭֵ��˵����û��ʼ��һ�η���
		{
			bytestocopy = MSSandTCPIPHeader;	
			DestionationOffset = 0;
			SourceOffset = 0;
			NdisCopyFromNetBufferToNetBuffer(currentNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)
				goto EXIT;

			currentNB->DataLength = bytestocopy;
			currentNB->CurrentMdl->ByteCount = currentNB->DataLength;	//currentNB->CurrentMdlOffset; ��ֵΪ0
			remainDataLen -= randomMSS;

			//	updatae ipH
			PUCHAR ipHeader = NdisGetDataBuffer(currentNB, IPHeaderLen, NULL, 1, 0);

			//updateIPHeader(ipHeader, IPHeaderLen, MSSandTCPIPHeader, ipFlags, 0);

			updateTCPchecksum(ipHeader, ipHeader + IPHeaderLen, ipHeader + TCPIPHeadersLen, TCPHeaderLen, randomMSS);

		}
		else {	// ������ǵ�һƬ����Ҫ��copyͷ����Ȼ����Ѿ��������payloadλ�ÿ�ʼ��������

			bytestocopy = TCPIPHeadersLen;
			DestionationOffset = 0;
			SourceOffset = 0;
			NdisCopyFromNetBufferToNetBuffer(currentNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)
				goto EXIT;

			bytestocopy = currentMDLSize - TCPIPHeadersLen;
			DestionationOffset = TCPIPHeadersLen;							// des������Ŀ��NB��TCP��IP�ײ�
			SourceOffset = TCPIPHeadersLen + payloadLen - remainDataLen;	// src������ԴNB���ײ����Ѿ����ƹ���payload
			NdisCopyFromNetBufferToNetBuffer(currentNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
				goto EXIT;

			currentNB->DataLength = currentMDLSize;
			currentNB->CurrentMdl->ByteCount = currentNB->DataLength;	//currentNB->CurrentMdlOffset; ��ֵΪ0
			
			PUCHAR ipHeader = NdisGetDataBuffer(currentNB, IPHeaderLen, NULL, 1, 0);

			//updateIPHeader(ipHeader, IPHeaderLen, currentMDLSize, ipFlags, 0);

			updateTCPSeqNumber(ipHeader+IPHeaderLen, payloadLen - remainDataLen);

			updateTCPchecksum(ipHeader, ipHeader + IPHeaderLen, ipHeader + TCPIPHeadersLen, TCPHeaderLen, bytestocopy);

			remainDataLen -= bytescopied;
		}
	}



	if (outbound) {
		status = FwpsInjectNetworkSendAsync(
			injection_handle,
			NULL,
			0,
			pendedPacket->compartmentId,
			CopyLayerdata,
			IPInjectionComplete,
			pendedPacket
		);

	}
	else {
		status = FwpsInjectNetworkReceiveAsync(
			injection_handle,
			NULL,
			0,
			pendedPacket->compartmentId,
			pendedPacket->interfaceIndex,
			pendedPacket->subInterfaceIndex,
			CopyLayerdata,
			IPInjectionComplete,
			pendedPacket
		);
	}

	if (!NT_SUCCESS(status))
	{
		goto EXIT;
	}
	else {
		// ע��ɹ���Ҫ�ͷ�pendedPacket��ipHeaderInfo
		return TRUE;
	}

EXIT:
	if (pendedPacket != NULL) {
		ExFreePoolWithTag(pendedPacket, TCPCALLOUT_POOL_TAG);
		pendedPacket = NULL;
	}
		
	// ���ע��ʧ�ܣ����߲���Ҫע�룩������Ҫ�жϲ��ͷ�Copylayerdata
	if (CopyLayerdata != NULL) {
		IPfragementFree(CopyLayerdata);
	}	

	return FALSE;
}


NTSTATUS IPNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	
	return STATUS_SUCCESS;
}






