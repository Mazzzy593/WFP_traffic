
/*-----------------------------------------------------------------------------
  FILE README

		���ļ��� ShaperQueuePacket �������룬��Ҫ��MAC���NET_BUFFER_LIST�ṹ���layerdata
	����IP��Ƭ��MAC֡��䴦�����û���������ָ��MTU��С������IP��Ƭ���ƣ�������ͨ������MAC֡
	����䳤�ȣ����������ݰ����ȡ�

-----------------------------------------------------------------------------*/
#include "common.h"

/*-----------------------------------------------------------------------------
  POOL Tag
-----------------------------------------------------------------------------*/
#define IP_FRAGEMENT_POOL_TAG 'ifpt'
#define CLONE_DATA_POOL_TAG 'cdpt'

/*-----------------------------------------------------------------------------
  GLOBALS
-----------------------------------------------------------------------------*/
// for debug
BOOLEAN MACFrameTestFlag = TRUE;
BOOLEAN IPTestFlag = TRUE;
BOOLEAN DEBUGFLAG = TRUE;
PUCHAR DataPoolforMdl;

extern BOOLEAN IPFragment_enable;
extern BOOLEAN MACpad_enable;

/*-----------------------------------------------------------------------------
  Function declaration
-----------------------------------------------------------------------------*/
VOID DbgprintMAC_Header(PUCHAR macFrame);

VOID DbgprintIPV4_HEADER(IPV4_HEADER* ipHeader);

static UINT16 WinDivertCalcChecksum(PVOID pseudo_header, UINT16 pseudo_header_len, PVOID data, UINT len);

/*-----------------------------------------------------------------------------
  Function implementation
-----------------------------------------------------------------------------*/
VOID DbgprintMAC_Header(PUCHAR macFrame)	// �����ֽڴ�ӡMAC֡ͷ
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MAC frame Ethernet header,Des: %02X:%02X:%02X:%02X:%02X:%02X + Src: %02X:%02X:%02X:%02X:%02X:%02X + Type:%02X:%02X\n",
		macFrame[0], macFrame[1], macFrame[2], macFrame[3], macFrame[4], macFrame[5], macFrame[6], macFrame[7],
		macFrame[8], macFrame[9], macFrame[10], macFrame[11], macFrame[12], macFrame[13]);
}

VOID DbgprintIPV4_HEADER(IPV4_HEADER* ipHeader)	// ����IPV4_HEADER�ṹ���ӡip�ײ�
{
	// ��ӡiph
	DbgPrint("Ver:%02x Hlen:%02x TotalLen: %d(byte) Flags:%x FragOffset: %d(byte) Checksum: %04x Src: %d.%d.%d.%d Des: %d.%d.%d.%d \n",
		ipHeader->Version, ipHeader->HeaderLength, ipHeader->TotalLength,
		ipHeader->Flags, ipHeader->FragmentOffset * 8, ipHeader->Checksum,
		(ipHeader->SrcAddress >> 24) & 0xFF, (ipHeader->SrcAddress >> 16) & 0xFF, (ipHeader->SrcAddress >> 8) & 0xFF, ipHeader->SrcAddress & 0xFF,
		(ipHeader->DesAddress >> 24) & 0xFF, (ipHeader->DesAddress >> 16) & 0xFF, (ipHeader->DesAddress >> 8) & 0xFF, ipHeader->DesAddress & 0xFF);
}

VOID IPV4_HEADER_INIT(IPV4_HEADER* ipH, PUCHAR ipP)  // ͨ��ipPacket�����IPV4_HEADER�ṹ��
{
	//ipH->Version = ipP[0] >> 4;           // IPv4 IPЭ��汾��Ϊ4����һ��IPЭ��汾��Ϊ6��
	ipH->Version = 0x4;
	ipH->HeaderLength = (ipP[0] & 0xF) * 4;   // �ײ�����һ���� 5*4 = 20�ֽ�
	ipH->TypeOfService = ipP[1];
	ipH->TotalLength = (USHORT)((ipP[2] << 8) | ipP[3]);
	ipH->Identification = (USHORT)((ipP[4] << 8) | ipP[5]);
	ipH->Flags = ipP[6] >> 5;
	ipH->FragmentOffset = (USHORT)(((ipP[6] & 0x1F) << 8) | ipP[7]);
	ipH->TimeToLive = ipP[8];
	ipH->Protocol = ipP[9];
	ipH->Checksum = (USHORT)((ipP[10] << 8) | ipP[11]);        // ��֪���ǲ��ǰ��մ�˴���ģ�Ӧ����
	ipH->SrcAddress = (ULONG)((ipP[12] << 24) | (ipP[13] << 16) | (ipP[14] << 8) | ipP[15]);
	ipH->DesAddress = (ULONG)((ipP[16] << 24) | (ipP[17] << 16) | (ipP[18] << 8) | ipP[19]);
}


static UINT16 GetIpCheckSum(PUCHAR ipHeader, UINT16 ipHeaderLen)	// ����UINT16���͵�IP�ײ�checksum
{
	int cksum = 0;
	int index = 0;
	*(ipHeader + 10) = 0;
	*(ipHeader + 11) = 0;
	if (ipHeaderLen % 2 != 0)
		return 0;
	while (index < ipHeaderLen)
	{
		cksum += *(ipHeader + index + 1);
		cksum += *(ipHeader + index) << 8;
		index += 2;
	}
	while (cksum > 0xffff)
	{
		cksum = (cksum >> 16) + (cksum & 0xffff);
	}
	return ~cksum;
}

VOID updateIPHeader(PUCHAR ipHeader,UINT16 headerLength,ULONG totalLength,UCHAR Flags,UINT32 FragmentOffset)
{
	// �����ṩ�Ĳ���������IP���ݰ����ײ���Ϣ
	// update ipH
	ipHeader[2] = *(((PUCHAR)(&totalLength)) + 1);
	ipHeader[3] = *(((PUCHAR)(&totalLength)));			// ����totallength
	ipHeader[6] = *(((PUCHAR)(&FragmentOffset)) + 1);	// ��Ϊ����Ƭ��������ʱ���ø���fragmentOffset
	ipHeader[7] = *((PUCHAR)(&FragmentOffset));

	ipHeader[6] &= 0b00011111;	// ������
	ipHeader[6] |= Flags;		// ����flag

	// �����ײ�У���
	UINT16 checksum = GetIpCheckSum(ipHeader, headerLength);	// Ҫ����ͷ��check�ܷ����
	//UINT16 checksum = WinDivertCalcChecksum(NULL, 0, ipHeader, ipHeaderInfo->HeaderLength);
	ipHeader[10] = *(((PUCHAR)(&checksum)) + 1);
	ipHeader[11] = *(((PUCHAR)(&checksum)));
}


BOOLEAN IPFragment_inbound(_Inout_opt_ void* layerData, PNET_BUFFER_LIST* pCopyLayerdata, UINT MACPadLen)
{
#ifdef DEBUG
	if (DEBUGFLAG){
		DbgBreakPoint();
		DEBUGFLAG = FALSE;
	}
#endif
	LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
	ULONG random = RtlRandomEx(&now.LowPart) % 100;
	if (random > SELF_IPFragmentRate)
		return FALSE;

	UINT SELF_MTU = SELF_MTUmin + RtlRandomEx(&now.LowPart) % (SELF_MTUmax - SELF_MTUmin);	// �����MTU

	NTSTATUS status;
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);// inbound һ��NBLֻ��һ��NB
	// ����nb��ָ��λ�ã���Ϊ��ջ����������ָ��IPͷ�Ŀ�ʼ��
	// ���ﱾ���ǵ�����datalength��currentmdloffset��return֮��Ҫ����advance����
	status = NdisRetreatNetBufferDataStart(nb, 14, 0, 0);

	PNET_BUFFER_LIST currentNBL = NULL;
	PIPV4_HEADER ipHeaderInfo = (PIPV4_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPV4_HEADER), CLONE_DATA_POOL_TAG);
	ULONG MaxFragmentNum = 0;
	ULONG remainDataLen = 0;
	UINT32 FragmentOffset = 0;	// ��λ��(8bytes)�����ڼ�¼��ǰ�������NB��offset
	UCHAR tmpFlags = 0;			// ���ڼ�¼��ǰ�������NB��flags

	// NdisCopyFromNetBufferToNetBuffer����Ҫ�õĲ�������
	ULONG bytestocopy = 0;
	ULONG bytescopied = 0;
	ULONG DestionationOffset = 0;
	ULONG SourceOffset = 0;

	PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
	PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

	// ɸѡ��Ҫ����Ƭ��NB������Ҫ��Ƭ��ֱ��return False
	if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00))  // 12��13��MAC frame type�ֶΣ�0800�����ڲ���IPv4����
		return FALSE;												// ��IPv4�����ݰ���������
	IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);				// MAC�ײ���СΪ14�ֽڣ�+14�����IP�ײ��Ŀ�ʼλ��
	if (ipHeaderInfo->TotalLength <= SELF_MTU)						// С��SELF_MTU�����ݰ���������
		return FALSE;

	UCHAR nbIP_Flags = 0;
	if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2) 		// ���ԭIP���ݰ���������Ƭ�������Ǿ��ֶ���DFΪ0
		nbIP_Flags = 0b00000000;
	else if (ipHeaderInfo->Flags == 1)	// more fragments
		nbIP_Flags = 0b00100000;
	else
		return FALSE; // IP���ݰ�Flagsֻ��������������������������

	UINT32 nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;// ������˵��ֻ��Ҫ����һ��OFFSET�Ϳ��ԣ��ñ��������ò���

	// SELF_MTU��ز���
	UINT32 SELF_MTUpayloadLen = (SELF_MTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// ����IP���ݰ�����ȥIP�ײ����payload����.��Ϊ��Ƭ���ֽ�ƫ�Ʊ�����8��������
	UINT32 SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// ����IP���ݰ�������IP�ײ����ܳ���
	UINT32 SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// ����IP���ݰ�������IP�ײ���MAC֡ͷ�ĳ���
	UINT32 SELF_MDLDataSize = SELF_MTUandMACSize + 0x20;							// ����MDL����С����������0x20�����ࣩ
	UINT32 SELF_nbDataLength = SELF_MDLDataSize;									// ����NET_BUFFER��datalength
	UINT32 SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;

	// MaxFragmentNum����Ƭ����
	UINT32 totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	MaxFragmentNum = (totalPayloadLength % SELF_MTUpayloadLen) > 0 ? (totalPayloadLength / SELF_MTUpayloadLen + 1) : totalPayloadLength / SELF_MTUpayloadLen;
	
	// remainDataLen����ǰNB�л���Ҫ������payload����
	remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;

	for (UINT i = 0; i < MaxFragmentNum; i++)
	{
		if (i == 0)
		{
			PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
			if (!pmdl)
				return FALSE;
			DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SELF_MDLDataSize, CLONE_DATA_POOL_TAG);	//����һ���㹻�Ŀռ�
			if (!DataPoolforMdl)
				return FALSE;
			RtlZeroMemory(DataPoolforMdl, SELF_MDLDataSize);
			pmdl = IoAllocateMdl(DataPoolforMdl, SELF_MDLDataSize, FALSE, FALSE, NULL);
			MmBuildMdlForNonPagedPool(pmdl);

			//����NBL
			status = FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, pmdl, 0, SELF_MDLDataSize, pCopyLayerdata);
			if (!NT_SUCCESS(status))
				return FALSE;

			PNET_BUFFER tmpnb = NET_BUFFER_LIST_FIRST_NB(*pCopyLayerdata);	//ȡ��һ��NB

			bytestocopy = SELF_MTUandMACSize;	// ��Ҫcopy MACͷ����IPͷ����������8��payload��
			DestionationOffset = 0;				// DestionationOffset=0,SourceOffset=0
			SourceOffset = 0;
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)
				return FALSE;

			tmpnb->DataLength = SELF_MTUandMACSize;
			tmpnb->CurrentMdl->ByteCount = tmpnb->DataLength + tmpnb->CurrentMdlOffset;
			remainDataLen -= SELF_MTUpayloadLen;

			// get ipH
			PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(tmpnb->CurrentMdl, NormalPagePriority);
			if (!tmpMdlStart)
				return FALSE;
			PUCHAR ipHeader = (PUCHAR)tmpMdlStart + tmpnb->CurrentMdlOffset + 14;

			tmpFlags = 0b00100000;
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, SELF_MTUDataLen, tmpFlags, nbIP_FragmentOffset);

			//NdisAdvanceNetBufferDataStart(tmpnb, 14, FALSE, 0);

			currentNBL = *pCopyLayerdata;

		}else {
			// �ȹ���mdl
			// ��ΪAllocateSize�����滻�����⣬�����˲���bug
			UINT AllocateSize = remainDataLen > SELF_MTU ? SELF_MDLDataSize : remainDataLen + 34 + 0x20;

			PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
			if (!pmdl)
				return FALSE;
			DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, AllocateSize, CLONE_DATA_POOL_TAG);	//����һ���ʵ��Ŀռ�
			if (!DataPoolforMdl)
				return FALSE;
			RtlZeroMemory(DataPoolforMdl, AllocateSize);
			pmdl = IoAllocateMdl(DataPoolforMdl, AllocateSize, FALSE, FALSE, NULL);
			MmBuildMdlForNonPagedPool(pmdl);

			PNET_BUFFER_LIST tmpNBL = (PNET_BUFFER_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(NET_BUFFER_LIST), CLONE_DATA_POOL_TAG);
			RtlZeroMemory(tmpNBL, sizeof(NET_BUFFER_LIST));

			status = FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, pmdl, 0, AllocateSize, &tmpNBL);
			if (!NT_SUCCESS(status))
				return FALSE;

			PNET_BUFFER tmpnb = NET_BUFFER_LIST_FIRST_NB(tmpNBL);

			// �Ȱ�MAC�ײ���IP�ײ����Ƶ���Ӧλ��
			bytestocopy = SELF_MACHandIPHLen;		// ��Ҫ�����ײ���Ҫ14+iphlen�ֽ�
			DestionationOffset = 0;					// currentoffset����������Ϊ2
			SourceOffset = 0;						// ��nb����ʼλ�ÿ�ʼ����
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
				return FALSE;

			// �������ײ��󣬿�ʼ���ƴ˷�Ƭ��data
			bytestocopy = remainDataLen > SELF_MTUpayloadLen ? SELF_MTUpayloadLen : remainDataLen;
			DestionationOffset = SELF_MACHandIPHLen;					// des������Ŀ��NB��TCP��IP�ײ�
			SourceOffset = SELF_MACHandIPHLen + i * SELF_MTUpayloadLen;	// src������ԴNB���ײ����Ѿ����ƹ���payload
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
				return FALSE;

			// ������ɺ�����nb��datalength��CurrentMdl->ByteCount
			tmpnb->DataLength = SELF_MACHandIPHLen + bytestocopy;
			tmpnb->CurrentMdl->ByteCount = tmpnb->DataLength + tmpnb->CurrentMdlOffset;
			remainDataLen -= bytescopied;

			// get iph
			PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(tmpnb->CurrentMdl, NormalPagePriority);
			if (!tmpMdlStart)
				return FALSE;
			PUCHAR ipHeader = (PUCHAR)tmpMdlStart + tmpnb->CurrentMdlOffset + 14;

			ULONG tmpTotalLen = bytestocopy + ipHeaderInfo->HeaderLength;
			FragmentOffset = nbIP_FragmentOffset + (i * SELF_MTUpayloadLen) / 8;
			if (remainDataLen > 0)
				tmpFlags = 0b00100000;	// ���һƬ֮ǰ��flags������001
			else
				tmpFlags = nbIP_Flags;	// ���һƬ��flagsӦ��ά�ֳ�ʼ��flags(����������flags)
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, tmpTotalLen, tmpFlags, FragmentOffset);

			// NdisAdvanceNetBufferDataStart(tmpnb, 14, FALSE, 0);

			NET_BUFFER_LIST_NEXT_NBL(currentNBL) = tmpNBL;
			currentNBL = NET_BUFFER_LIST_NEXT_NBL(currentNBL);

		}
	}

		if (remainDataLen != 0) {
		return FALSE;		// ���remainDataLen����0��˵������ʧ��
	}
	else {
		return TRUE;
	}

}




BOOLEAN IPFragment(BOOLEAN outbound,
	_Inout_opt_ void* layerData, 
	PNET_BUFFER_LIST* pCopyLayerdata )
{
#ifdef NOGUI
	IPFragment_enable = TRUE;
	SELF_IPFragmentRate = 100;
	SELF_MTUmax = SELF_MTUmin = 1200;
#endif

	if (!IPFragment_enable) {
		return FALSE;
	}
#ifdef DEBUG
	if (IPTestFlag)
	{
		DbgBreakPoint();
		IPTestFlag = FALSE;
	}
#endif
	//if (!outbound)
	//{
	//	return IPFragment_inbound(layerData, pCopyLayerdata, MACPadLen);
	//}

	// ����������ݰ�
	LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
	ULONG random = RtlRandomEx(&now.LowPart) % 100;
	if (random > SELF_IPFragmentRate)
		return FALSE;

	UINT randomMTU = SELF_MTUmin + RtlRandomEx(&now.LowPart) % ((SELF_MTUmax - SELF_MTUmin)>0 ? (SELF_MTUmax - SELF_MTUmin):1);	// �����MTU
	
	UINT randomMacPadLen = SELF_MACpadmin + RtlRandomEx(&now.LowPart) % ((SELF_MACpadmax - SELF_MACpadmin) > 0 ? (SELF_MACpadmax - SELF_MACpadmin) : 1);

#ifdef NOGUI
	randomMTU = 1200;
#endif // NOGUI

	NTSTATUS status;

	// ������Ҫ������������������NB��
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);
	PNET_BUFFER currentNB = NULL;	// �����currentNB��ָ��ǰ��������NET_BUFFER_LIST�����һ��NET_BUFFER
	PIPV4_HEADER ipHeaderInfo = (PIPV4_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPV4_HEADER), CLONE_DATA_POOL_TAG);
	ULONG MaxFragmentNum = 0;
	ULONG remainDataLen = 0;
	UINT32 FragmentOffset = 0;	// ��λ��(8bytes)�����ڼ�¼��ǰ�������NB��offset
	UCHAR tmpFlags = 0;			// ���ڼ�¼��ǰ�������NB��flags
	// NdisCopyFromNetBufferToNetBuffer����Ҫ�õĲ�������
	ULONG bytestocopy = 0;
	ULONG bytescopied = 0;
	ULONG DestionationOffset = 0;
	ULONG SourceOffset = 0;

	///////////////// �Ե�һ���NB����ȡ��ͷ����Ϣ������һЩ������ֵ --begin ////////////////////////////////////////////////////////////////
	PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
	PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

	if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00))  // 12��13��MAC frame type�ֶΣ�0800�����ڲ���IPv4����
		return FALSE;												// ��IPv4�����ݰ���������
	IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);				// MAC�ײ���СΪ14�ֽڣ�+14�����IP�ײ��Ŀ�ʼλ��
	if (ipHeaderInfo->TotalLength <= randomMTU)						// С��SELF_MTU�����ݰ���������
		return FALSE;

	UCHAR nbIP_Flags=0;
	if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2) 		// ���ԭIP���ݰ���������Ƭ�������Ǿ��ֶ���DFΪ0
		nbIP_Flags = 0b00000000;
	else if (ipHeaderInfo->Flags == 1)
		nbIP_Flags = 0b00100000;
	else 
		return FALSE; // IP���ݰ�Flagsֻ��������������������������

	UINT32 nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;// ������˵��ֻ��Ҫ����һ��OFFSET�Ϳ��ԣ��ñ��������ò���

	UINT32 SELF_MTUpayloadLen = (randomMTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// ����IP���ݰ�����ȥIP�ײ����payload����.��Ϊ��Ƭ���ֽ�ƫ�Ʊ�����8��������
	UINT32 SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// ����IP���ݰ�������IP�ײ����ܳ���
	UINT32 SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// ����IP���ݰ�������IP�ײ���MAC֡ͷ�ĳ���
	UINT32 SELF_MDLDataSize = SELF_MTUandMACSize + 0x32;							// ����MDL����С����������0x20�����ࣩ
	UINT32 SELF_nbDataLength = SELF_MDLDataSize;									// ����NET_BUFFER��datalength
	UINT32 SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;					// MAC֡ͷ��IP�ײ��ĳ��ȣ���������¹̶�����IP�ײ����ܳ��Ȳ�һ��
	// ȷ����Ƭ����
	UINT32 totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	MaxFragmentNum = (totalPayloadLength%SELF_MTUpayloadLen) > 0 ? (totalPayloadLength/SELF_MTUpayloadLen +1): totalPayloadLength / SELF_MTUpayloadLen; 
	// ��ǰNB�л���Ҫ������payload����
	remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	///////////////// �Ե�һ���NB����ȡ��ͷ����Ϣ������һЩ������ֵ --end /////////////////////////////////////////////////////////////

	////////////////  MDL��ش��룬ֻ��Ϊ�˹���NBLʱʹ��FwpsAllocateNetBufferAndNetBufferList������������Ҫ�ֶ�����MDL  --begin/////////
	// PMDL!!!!!!!!!!!�ڴ��ͷ����������
	PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
	if (!pmdl)
		return FALSE;
	// �����������ƬDataPoolforMdl�ռ䣬�����������packetdata�ģ�
	DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SELF_MDLDataSize, CLONE_DATA_POOL_TAG);	//����һ���㹻�Ŀռ�
	if (!DataPoolforMdl) {
		return FALSE;
	}
	RtlZeroMemory(DataPoolforMdl, SELF_MDLDataSize);
	pmdl = IoAllocateMdl(DataPoolforMdl, SELF_MDLDataSize, FALSE, FALSE, NULL);
	MmBuildMdlForNonPagedPool(pmdl);
	/////////////////	MDL��ش���	--end	////////////////////////////////////////////////////////////////////////////////////////////
	
	///////////////// ������forѭ���н��е�һ��NB�Ĵ�������Ϊ��һ��NB�漰��NBL�Ĺ��죬���Ե�������������� --begin /////////////////////
	for (UINT i = 0; i < MaxFragmentNum; i++)
	{
		if (i == 0)
		{
			status = FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, pmdl, 0, SELF_MDLDataSize, pCopyLayerdata);
			if (!NT_SUCCESS(status))
				return FALSE;
			PNET_BUFFER tmpnb = NET_BUFFER_LIST_FIRST_NB(*pCopyLayerdata);	//ȡ��һ��NB
			
			bytestocopy = SELF_MTUandMACSize;	// ��Ҫcopy MACͷ����IPͷ����������8��payload��
			DestionationOffset = 0;				// DestionationOffset=0,SourceOffset=0
			SourceOffset = 0;
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)
			{
				// ���������ͷŲ�����
				FwpsFreeNetBufferList(*pCopyLayerdata);
				return FALSE;
			}
			tmpnb->DataLength = SELF_MTUandMACSize;
			tmpnb->CurrentMdl->ByteCount = tmpnb->DataLength + tmpnb->CurrentMdlOffset;
			remainDataLen -= SELF_MTUpayloadLen;

			// get ipH
			PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(tmpnb->CurrentMdl, NormalPagePriority);
			if (!tmpMdlStart)
				return FALSE;
			PUCHAR ipHeader = (PUCHAR)tmpMdlStart + tmpnb->CurrentMdlOffset + 14;

			// update ipH
			// �����ǰ���ݰ�û�б���Ƭ����ôFragmentOffsetӦ������0��
			// �����ǰ���ݰ��Ѿ�����Ƭ�ˣ�FragmentOffset��ԭʼ��nbIP_FragmentOffset
			// ��flag��һ������Ϊ001
			tmpFlags = 0b00100000;
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, SELF_MTUDataLen, tmpFlags, nbIP_FragmentOffset);

			// MAC���
			if (RtlRandomEx(&now.LowPart) % 100 < SELF_MACpadRate)
			{
				if (MACpad_enable && randomMacPadLen > 0)
				{
					if (tmpnb->DataLength + randomMacPadLen >= SELF_MDLDataSize)
					{
						tmpnb->DataLength = SELF_MDLDataSize;
						tmpnb->CurrentMdl->ByteCount = tmpnb->DataLength + tmpnb->CurrentMdlOffset;
					}
					else {
						tmpnb->DataLength += randomMacPadLen;
						tmpnb->CurrentMdl->ByteCount += randomMacPadLen;
					}
				}
			}
			currentNB = tmpnb;
		}
		else {		
			// ��i!=0����ʱ�Ѿ������õ�һ����Ƭ
			// ͨ��Allocate���Retreat���õ������ʵ����ݳ��ȵ�MDL��NB
			PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
			status = NdisRetreatNetBufferDataStart(newNB, SELF_nbDataLength, 0, 0);
			if (!NT_SUCCESS(status)) 
				return FALSE;

			// �Ȱ�MAC�ײ���IP�ײ����Ƶ���Ӧλ��
			bytestocopy = SELF_MACHandIPHLen;		// ��Ҫ�����ײ���Ҫ14+iphlen�ֽ�
			DestionationOffset = 0;					// currentoffset����������Ϊ2
			SourceOffset = 0;						// ��nb����ʼλ�ÿ�ʼ����
			NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
				return FALSE;

			// �������ײ��󣬿�ʼ���ƴ˷�Ƭ��data
			bytestocopy = remainDataLen > SELF_MTUpayloadLen ? SELF_MTUpayloadLen : remainDataLen;
			DestionationOffset = SELF_MACHandIPHLen;					// des������Ŀ��NB��TCP��IP�ײ�
			SourceOffset = SELF_MACHandIPHLen + i * SELF_MTUpayloadLen;	// src������ԴNB���ײ����Ѿ����ƹ���payload
			NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
				return FALSE;

			// ������ɺ�����nb��datalength��CurrentMdl->ByteCount
			newNB->DataLength = SELF_MACHandIPHLen + bytestocopy;
			newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
			remainDataLen -= bytescopied;

			// get iph
			PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
			if (!tmpMdlStart)
				return FALSE;
			PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;

			ULONG tmpTotalLen = bytestocopy + ipHeaderInfo->HeaderLength;
			FragmentOffset = nbIP_FragmentOffset + (i * SELF_MTUpayloadLen) / 8;
			if (remainDataLen > 0)
				tmpFlags = 0b00100000;	// ���һƬ֮ǰ��flags������001
			else
				tmpFlags = nbIP_Flags;	// ���һƬ��flagsӦ��ά�ֳ�ʼ��flags
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, tmpTotalLen, tmpFlags, FragmentOffset);
			
			// MAC���
			if (RtlRandomEx(&now.LowPart) % 100 < SELF_MACpadRate) {
				if (MACpad_enable && randomMacPadLen > 0)
				{
					if (newNB->DataLength + randomMacPadLen >= SELF_MTUandMACSize)
					{
						newNB->DataLength = SELF_MTUandMACSize;
						newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
					}
					else {
						newNB->DataLength += randomMacPadLen;
						newNB->CurrentMdl->ByteCount += randomMacPadLen;
					}
				}
			}
			NET_BUFFER_NEXT_NB(currentNB) = newNB;
			currentNB = NET_BUFFER_NEXT_NB(currentNB);
		}
	}

	///////////////////���е�һ��NB�Ĵ��� --end ////////////////////////////////////////////////////////////////////////////////////////

	///////////////// �������һ��NB�󣬵������к���NB�Ĵ��� --begin////////////////////////////////////////////////////////////////////
	if (remainDataLen != 0){
		return FALSE;		// ���remainDataLen����0��˵������ʧ��
	}
	else {	
		// ��ȷ�������һ��NB�����ִ��������NB���������һ����˵�������
		// �����������pingһ������1472�����ݰ���һ��NBL�ͻ��ж��NB
		nb = NET_BUFFER_NEXT_NB(nb);
		if (nb == NULL)
			return TRUE;

		// ��ʱ�����ж����NB��Ҫ����������whileѭ��
		while (nb)
		{
			BOOLEAN StraightCopyFlag = FALSE;
			currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
			NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

			if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00)) {
				StraightCopyFlag = TRUE;		// ���������������������������������Ҳ�ܴ�����ֱ��copy NB.datalength�������ݹ�ȥ�Ϳ���
			}
			else {
				IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);	// ֻ��IPV4Э��ģ��Ż�����ʼ��IPH
				if (ipHeaderInfo->TotalLength <= randomMTU)
					StraightCopyFlag = TRUE;	// ���IP���ĳ��Ȳ���SELF_MTU,ͬ��Ҳ��ֱ�Ӹ���
			}	
			if (StraightCopyFlag)
			{
				// ͨ��Allocate���Retreat���õ������ʵ�����MDL��NB
				PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
				status = NdisRetreatNetBufferDataStart(newNB, nb->DataLength, 0, 0);
				if (!NT_SUCCESS(status))
					return FALSE;

				// �Ȱ�MAC�ײ���IP�ײ����Ƶ���Ӧλ��
				bytestocopy = nb->DataLength;			// ��Ҫ����NB������data
				DestionationOffset = 0;					// ����Ϊ0
				SourceOffset = 0;						// ��nb����ʼλ�ÿ�ʼ����
				NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
				if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
					return FALSE;

				newNB->DataLength = nb->DataLength;
				newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
				remainDataLen = 0;

				// �������ԣ�����Ҫ�����Լ���д��ֱ�Ӹ���֮��IPcheck�ֶ�Ϊ0������wiresharkץ�������Ĳ���0��
				// �������������������IPcheck�Ƿ�Ϊ0�����Ϊ0���Զ����㣬���������Լ������NBL������û��Ϊ���Ǽ���check
				if (ipHeaderInfo->TotalLength <= randomMTU) {
					// get iph
					PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
					if (!tmpMdlStart)
						return FALSE;
					PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;
					UINT16 checksum = GetIpCheckSum(ipHeader, ipHeaderInfo->HeaderLength);	// Ҫ����ͷ��check�ܷ����
					ipHeader[10] = *(((PUCHAR)(&checksum)) + 1);
					ipHeader[11] = *(((PUCHAR)(&checksum)));
				}

				NET_BUFFER_NEXT_NB(currentNB) = newNB;
				currentNB = NET_BUFFER_NEXT_NB(currentNB);

				nb = NET_BUFFER_NEXT_NB(nb);			
				continue;		// �뿪����whileѭ��
			}
			else {	// StraightCopyFlagΪfalse����ζ��ǰNB��Ҫ����IP��Ƭ
				if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2)		// ���ԭIP���ݰ���������Ƭ��DFλ=1�����Ǿ��ֶ���DFΪ0
					nbIP_Flags = 0b00000000;		// Դ IP flags
				else if (ipHeaderInfo->Flags == 1)								
					nbIP_Flags = 0b00100000;
				else
					return FALSE; // IP���ݰ�Flagsֻ��������������������������

				nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;

				SELF_MTUpayloadLen = (randomMTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// ����IP���ݰ�����ȥIP�ײ����payload����.��Ϊ��Ƭ���ֽ�ƫ�Ʊ�����8��������
				SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// ����IP���ݰ�������IP�ײ����ܳ���
				SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// ����IP���ݰ�������IP�ײ���MAC֡ͷ�ĳ���
				SELF_MDLDataSize = SELF_MTUandMACSize + 0x20;							// ����MDL����С����������0x20�����ࣩ
				SELF_nbDataLength = SELF_MDLDataSize;									// ����NET_BUFFER��datalength
				SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;					// MAC֡ͷ��IP�ײ��ĳ��ȣ���������¹̶�����IP�ײ����ܳ��Ȳ�һ��
				// ȷ����Ƭ����
				totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
				MaxFragmentNum = (totalPayloadLength % SELF_MTUpayloadLen) > 0 ? (totalPayloadLength / SELF_MTUpayloadLen + 1) : totalPayloadLength / SELF_MTUpayloadLen;
				// ��ǰNB�л���Ҫ������payload����(������MACͷ����IPͷ��!!!!!)
				remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;

				for (UINT i = 0; i < MaxFragmentNum; i++) {
					// ͨ��Allocate���Retreat���õ������ʵ�����MDL��NB
					PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
					status = NdisRetreatNetBufferDataStart(newNB, SELF_nbDataLength, 0, 0);
					if (!NT_SUCCESS(status))
						return FALSE;

					if (i == 0) {	// �˴�ҲҪ���ǵ�һ����Ƭ�������
						bytestocopy = SELF_MTUandMACSize;	// ��Ҫcopy MACͷ����IPͷ�����������8��payload��
						DestionationOffset = 0;				//DestionationOffset=0,SourceOffset=0
						SourceOffset = 0;
						NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
						if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
							return FALSE;
						newNB->DataLength = SELF_MTUandMACSize;
						newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
						remainDataLen -= SELF_MTUpayloadLen;	// ע�⣬��һ����ƬЯ�������ݳ�����SELF_MTUpayloadLen

						// get ipH
						PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
						if (!tmpMdlStart)
							return FALSE;
						PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;

						// update ipH
						// �����ǰ���ݰ�û�б���Ƭ����ôFragmentOffsetӦ������0��
						// �����ǰ���ݰ��Ѿ�����Ƭ�ˣ�FragmentOffset��ԭʼ��nbIP_FragmentOffset
						// ��flag��һ������Ϊ001
						UCHAR tmpFlags = 0b00100000;
						updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, SELF_MTUDataLen, tmpFlags, nbIP_FragmentOffset);
					}
					else {
						// �Ȱ�MAC�ײ���IP�ײ����Ƶ���Ӧλ��
						bytestocopy = SELF_MACHandIPHLen;		// ��Ҫ�����ײ���Ҫ14+iphlen�ֽ�
						DestionationOffset = 0;					// currentoffset����������Ϊ2
						SourceOffset = 0;						// ��nb����ʼλ�ÿ�ʼ����
						NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
						if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
							return FALSE;

						// �������ײ��󣬿�ʼ���ƴ˷�Ƭ��data
						bytestocopy = remainDataLen > SELF_MTUpayloadLen ? SELF_MTUpayloadLen : remainDataLen;
						DestionationOffset = SELF_MACHandIPHLen;					// des������Ŀ��NB��TCP��IP�ײ�
						SourceOffset = SELF_MACHandIPHLen + i * SELF_MTUpayloadLen;	// src������ԴNB���ײ����Ѿ����ƹ���payload
						NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
						if (bytescopied != bytestocopy)			// �жϸ����Ƿ�ɹ�
							return FALSE;

						// ������ɺ�����nb��datalength��CurrentMdl->ByteCount
						newNB->DataLength = SELF_MACHandIPHLen + bytestocopy;
						newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
						// ������ƬЯ�������ݳ��ȿ�����SELF_MTUpayloadLen��Ҳ������ʣ��Ĳ���SELF_MTUpayloadLen������
						remainDataLen -= bytescopied;			

						// get iph
						PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
						if (!tmpMdlStart)
							return FALSE;
						PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;

						// update iph
						ULONG tmpTotalLen = bytestocopy + ipHeaderInfo->HeaderLength;
						FragmentOffset = nbIP_FragmentOffset + (i * SELF_MTUpayloadLen) / 8;
						if (remainDataLen > 0)
							tmpFlags = 0b00100000;	

						else 
							tmpFlags = nbIP_Flags;	

						updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, tmpTotalLen, tmpFlags, FragmentOffset);
					}

					NET_BUFFER_NEXT_NB(currentNB) = newNB;
					currentNB = NET_BUFFER_NEXT_NB(currentNB);
				}

				nb = NET_BUFFER_NEXT_NB(nb);
				continue;
			}
			
		}

		if (remainDataLen != 0)	
			return FALSE;
		else
			return TRUE;
	}

}



ULONG total_packet_count = 0;
ULONG total_NBL_mix_count = 0;





VOID zzpTypeOfNBLTest(_Inout_opt_ void* layerdata)
{

	//ULONG packet_count = 0;
	ULONG current_packet_count = 0;
	ULONG current_NBL_IPv4_count = 0;

	
	PNET_BUFFER buffer = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerdata);

	if (!buffer)
		return;

	while (buffer) {
		total_packet_count++;
		current_packet_count++;
		PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(buffer), NormalPagePriority);
		PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(buffer);
		
		if (NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00){
			current_NBL_IPv4_count++;
		}
		
		if (total_packet_count % 60 == 0) {
			DbgPrint("total_packet_count:%d,total_NBL_mix_count:%d,\n", total_packet_count, total_NBL_mix_count);
		}
		//data_length += NET_BUFFER_DATA_LENGTH(buffer);
		buffer = NET_BUFFER_NEXT_NB(buffer);
	}
	
	if (current_packet_count > 1 && current_NBL_IPv4_count < current_packet_count){
		total_NBL_mix_count++;
	}

	if (current_packet_count > 1) {
		DbgPrint("current_packet_count:%d,current_NBL_IPv4_count:%d\n", current_packet_count, current_NBL_IPv4_count);
	}

}


