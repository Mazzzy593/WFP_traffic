
/*-----------------------------------------------------------------------------
  FILE README

		该文件由 ShaperQueuePacket 函数进入，主要对MAC层的NET_BUFFER_LIST结构体的layerdata
	进行IP分片和MAC帧填充处理，用户可以自行指定MTU大小以用于IP分片控制，还可以通过设置MAC帧
	的填充长度，来控制数据包长度。

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

extern IPFragment_enable;
extern MACpad_enable;

/*-----------------------------------------------------------------------------
  Function declaration
-----------------------------------------------------------------------------*/
DbgprintMAC_Header(PUCHAR macFrame);

VOID DbgprintIPV4_HEADER(IPV4_HEADER* ipHeader);

static UINT16 WinDivertCalcChecksum(PVOID pseudo_header, UINT16 pseudo_header_len, PVOID data, UINT len);

/*-----------------------------------------------------------------------------
  Function implementation
-----------------------------------------------------------------------------*/
DbgprintMAC_Header(PUCHAR macFrame)	// 按照字节打印MAC帧头
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MAC frame Ethernet header,Des: %02X:%02X:%02X:%02X:%02X:%02X + Src: %02X:%02X:%02X:%02X:%02X:%02X + Type:%02X:%02X\n",
		macFrame[0], macFrame[1], macFrame[2], macFrame[3], macFrame[4], macFrame[5], macFrame[6], macFrame[7],
		macFrame[8], macFrame[9], macFrame[10], macFrame[11], macFrame[12], macFrame[13]);
}

VOID DbgprintIPV4_HEADER(IPV4_HEADER* ipHeader)	// 按照IPV4_HEADER结构体打印ip首部
{
	// 打印iph
	DbgPrint("Ver:%02x Hlen:%02x TotalLen: %d(byte) Flags:%x FragOffset: %d(byte) Checksum: %04x Src: %d.%d.%d.%d Des: %d.%d.%d.%d \n",
		ipHeader->Version, ipHeader->HeaderLength, ipHeader->TotalLength,
		ipHeader->Flags, ipHeader->FragmentOffset * 8, ipHeader->Checksum,
		(ipHeader->SrcAddress >> 24) & 0xFF, (ipHeader->SrcAddress >> 16) & 0xFF, (ipHeader->SrcAddress >> 8) & 0xFF, ipHeader->SrcAddress & 0xFF,
		(ipHeader->DesAddress >> 24) & 0xFF, (ipHeader->DesAddress >> 16) & 0xFF, (ipHeader->DesAddress >> 8) & 0xFF, ipHeader->DesAddress & 0xFF);
}

VOID IPV4_HEADER_INIT(IPV4_HEADER* ipH, PUCHAR ipP)  // 通过ipPacket，填充IPV4_HEADER结构体
{
	//ipH->Version = ipP[0] >> 4;           // IPv4 IP协议版本号为4，下一代IP协议版本号为6。
	ipH->Version = 0x4;
	ipH->HeaderLength = (ipP[0] & 0xF) * 4;   // 首部长度一般是 5*4 = 20字节
	ipH->TypeOfService = ipP[1];
	ipH->TotalLength = (USHORT)((ipP[2] << 8) | ipP[3]);
	ipH->Identification = (USHORT)((ipP[4] << 8) | ipP[5]);
	ipH->Flags = ipP[6] >> 5;
	ipH->FragmentOffset = (USHORT)(((ipP[6] & 0x1F) << 8) | ipP[7]);
	ipH->TimeToLive = ipP[8];
	ipH->Protocol = ipP[9];
	ipH->Checksum = (USHORT)((ipP[10] << 8) | ipP[11]);        // 不知道是不是按照大端储存的，应该是
	ipH->SrcAddress = (ULONG)((ipP[12] << 24) | (ipP[13] << 16) | (ipP[14] << 8) | ipP[15]);
	ipH->DesAddress = (ULONG)((ipP[16] << 24) | (ipP[17] << 16) | (ipP[18] << 8) | ipP[19]);
}


static UINT16 GetIpCheckSum(PUCHAR ipHeader, UINT16 ipHeaderLen)	// 计算UINT16类型的IP首部checksum
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
	// 根据提供的参数，更新IP数据包的首部信息
	// update ipH
	ipHeader[2] = *(((PUCHAR)(&totalLength)) + 1);
	ipHeader[3] = *(((PUCHAR)(&totalLength)));			// 更新totallength
	ipHeader[6] = *(((PUCHAR)(&FragmentOffset)) + 1);	// 因为是首片，所以暂时不用更新fragmentOffset
	ipHeader[7] = *((PUCHAR)(&FragmentOffset));

	ipHeader[6] &= 0b00011111;	// 先清零
	ipHeader[6] |= Flags;		// 添加flag

	// 更新首部校验和
	UINT16 checksum = GetIpCheckSum(ipHeader, headerLength);	// 要检验头部check能否算对
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

	UINT SELF_MTU = SELF_MTUmin + RtlRandomEx(&now.LowPart) % (SELF_MTUmax - SELF_MTUmin);	// 随机化MTU

	NTSTATUS status;
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);// inbound 一个NBL只有一个NB
	// 调整nb的指针位置，因为进栈流量本身是指向IP头的开始，
	// 这里本质是调整了datalength和currentmdloffset，return之后要重新advance处理
	status = NdisRetreatNetBufferDataStart(nb, 14, 0, 0);

	PNET_BUFFER_LIST currentNBL = NULL;
	PIPV4_HEADER ipHeaderInfo = (PIPV4_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPV4_HEADER), CLONE_DATA_POOL_TAG);
	ULONG MaxFragmentNum = 0;
	ULONG remainDataLen = 0;
	UINT32 FragmentOffset = 0;	// 单位是(8bytes)，用于记录当前构造的新NB的offset
	UCHAR tmpFlags = 0;			// 用于记录当前构造的新NB的flags

	// NdisCopyFromNetBufferToNetBuffer函数要用的参数变量
	ULONG bytestocopy = 0;
	ULONG bytescopied = 0;
	ULONG DestionationOffset = 0;
	ULONG SourceOffset = 0;

	PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
	PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

	// 筛选需要被分片的NB，不需要分片的直接return False
	if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00))  // 12和13是MAC frame type字段，0800代表内部是IPv4数据
		return FALSE;												// 非IPv4的数据包不做处理
	IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);				// MAC首部大小为14字节，+14后就是IP首部的开始位置
	if (ipHeaderInfo->TotalLength <= SELF_MTU)						// 小于SELF_MTU的数据包不作处理
		return FALSE;

	UCHAR nbIP_Flags = 0;
	if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2) 		// 如果原IP数据包不允许分片，那我们就手动置DF为0
		nbIP_Flags = 0b00000000;
	else if (ipHeaderInfo->Flags == 1)	// more fragments
		nbIP_Flags = 0b00100000;
	else
		return FALSE; // IP数据包Flags只有三种情况，其他情况不做处理

	UINT32 nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;// 正常来说，只需要叠加一下OFFSET就可以，该变量可能用不到

	// SELF_MTU相关参数
	UINT32 SELF_MTUpayloadLen = (SELF_MTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// 单个IP数据包，除去IP首部后的payload长度.因为分片的字节偏移必须是8的整数倍
	UINT32 SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// 单个IP数据包，包括IP首部的总长度
	UINT32 SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// 单个IP数据包，包括IP首部和MAC帧头的长度
	UINT32 SELF_MDLDataSize = SELF_MTUandMACSize + 0x20;							// 单个MDL的最小容量（留有0x20的冗余）
	UINT32 SELF_nbDataLength = SELF_MDLDataSize;									// 单个NET_BUFFER的datalength
	UINT32 SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;

	// MaxFragmentNum：分片数量
	UINT32 totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	MaxFragmentNum = (totalPayloadLength % SELF_MTUpayloadLen) > 0 ? (totalPayloadLength / SELF_MTUpayloadLen + 1) : totalPayloadLength / SELF_MTUpayloadLen;
	
	// remainDataLen：当前NB中还需要拷贝的payload长度
	remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;

	for (UINT i = 0; i < MaxFragmentNum; i++)
	{
		if (i == 0)
		{
			PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
			if (!pmdl)
				return FALSE;
			DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SELF_MDLDataSize, CLONE_DATA_POOL_TAG);	//分配一个足够的空间
			if (!DataPoolforMdl)
				return FALSE;
			RtlZeroMemory(DataPoolforMdl, SELF_MDLDataSize);
			pmdl = IoAllocateMdl(DataPoolforMdl, SELF_MDLDataSize, FALSE, FALSE, NULL);
			MmBuildMdlForNonPagedPool(pmdl);

			//构造NBL
			status = FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, pmdl, 0, SELF_MDLDataSize, pCopyLayerdata);
			if (!NT_SUCCESS(status))
				return FALSE;

			PNET_BUFFER tmpnb = NET_BUFFER_LIST_FIRST_NB(*pCopyLayerdata);	//取第一个NB

			bytestocopy = SELF_MTUandMACSize;	// 需要copy MAC头部、IP头部、能整除8的payload长
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
			// 先构造mdl
			// 因为AllocateSize忘记替换的问题，产生了部分bug
			UINT AllocateSize = remainDataLen > SELF_MTU ? SELF_MDLDataSize : remainDataLen + 34 + 0x20;

			PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
			if (!pmdl)
				return FALSE;
			DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, AllocateSize, CLONE_DATA_POOL_TAG);	//分配一个适当的空间
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

			// 先把MAC首部和IP首部复制到对应位置
			bytestocopy = SELF_MACHandIPHLen;		// 需要复制首部需要14+iphlen字节
			DestionationOffset = 0;					// currentoffset象征性设置为2
			SourceOffset = 0;						// 从nb的起始位置开始复制
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// 判断复制是否成功
				return FALSE;

			// 复制完首部后，开始复制此分片的data
			bytestocopy = remainDataLen > SELF_MTUpayloadLen ? SELF_MTUpayloadLen : remainDataLen;
			DestionationOffset = SELF_MACHandIPHLen;					// des：跳过目的NB的TCP和IP首部
			SourceOffset = SELF_MACHandIPHLen + i * SELF_MTUpayloadLen;	// src：跳过源NB的首部和已经复制过的payload
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// 判断复制是否成功
				return FALSE;

			// 复制完成后设置nb的datalength和CurrentMdl->ByteCount
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
				tmpFlags = 0b00100000;	// 最后一片之前的flags必须是001
			else
				tmpFlags = nbIP_Flags;	// 最后一片的flags应该维持初始的flags(经过处理的flags)
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, tmpTotalLen, tmpFlags, FragmentOffset);

			// NdisAdvanceNetBufferDataStart(tmpnb, 14, FALSE, 0);

			NET_BUFFER_LIST_NEXT_NBL(currentNBL) = tmpNBL;
			currentNBL = NET_BUFFER_LIST_NEXT_NBL(currentNBL);

		}
	}

		if (remainDataLen != 0) {
		return FALSE;		// 如果remainDataLen不是0，说明处理失败
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

	// 随机放行数据包
	LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
	ULONG random = RtlRandomEx(&now.LowPart) % 100;
	if (random > SELF_IPFragmentRate)
		return FALSE;

	UINT randomMTU = SELF_MTUmin + RtlRandomEx(&now.LowPart) % ((SELF_MTUmax - SELF_MTUmin)>0 ? (SELF_MTUmax - SELF_MTUmin):1);	// 随机化MTU
	
	UINT randomMacPadLen = SELF_MACpadmin + RtlRandomEx(&now.LowPart) % ((SELF_MACpadmax - SELF_MACpadmin) > 0 ? (SELF_MACpadmax - SELF_MACpadmin) : 1);

#ifdef NOGUI
	randomMTU = 1200;
#endif // NOGUI

	NTSTATUS status;

	// 部分重要变量声明（用于所有NB）
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)layerData);
	PNET_BUFFER currentNB = NULL;	// 这里的currentNB是指当前构建的新NET_BUFFER_LIST中最后一个NET_BUFFER
	PIPV4_HEADER ipHeaderInfo = (PIPV4_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPV4_HEADER), CLONE_DATA_POOL_TAG);
	ULONG MaxFragmentNum = 0;
	ULONG remainDataLen = 0;
	UINT32 FragmentOffset = 0;	// 单位是(8bytes)，用于记录当前构造的新NB的offset
	UCHAR tmpFlags = 0;			// 用于记录当前构造的新NB的flags
	// NdisCopyFromNetBufferToNetBuffer函数要用的参数变量
	ULONG bytestocopy = 0;
	ULONG bytescopied = 0;
	ULONG DestionationOffset = 0;
	ULONG SourceOffset = 0;

	///////////////// 对第一块的NB，获取其头部信息，并做一些变量赋值 --begin ////////////////////////////////////////////////////////////////
	PVOID currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
	PUCHAR NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

	if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00))  // 12和13是MAC frame type字段，0800代表内部是IPv4数据
		return FALSE;												// 非IPv4的数据包不做处理
	IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);				// MAC首部大小为14字节，+14后就是IP首部的开始位置
	if (ipHeaderInfo->TotalLength <= randomMTU)						// 小于SELF_MTU的数据包不作处理
		return FALSE;

	UCHAR nbIP_Flags=0;
	if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2) 		// 如果原IP数据包不允许分片，那我们就手动置DF为0
		nbIP_Flags = 0b00000000;
	else if (ipHeaderInfo->Flags == 1)
		nbIP_Flags = 0b00100000;
	else 
		return FALSE; // IP数据包Flags只有三种情况，其他情况不做处理

	UINT32 nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;// 正常来说，只需要叠加一下OFFSET就可以，该变量可能用不到

	UINT32 SELF_MTUpayloadLen = (randomMTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// 单个IP数据包，除去IP首部后的payload长度.因为分片的字节偏移必须是8的整数倍
	UINT32 SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// 单个IP数据包，包括IP首部的总长度
	UINT32 SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// 单个IP数据包，包括IP首部和MAC帧头的长度
	UINT32 SELF_MDLDataSize = SELF_MTUandMACSize + 0x32;							// 单个MDL的最小容量（留有0x20的冗余）
	UINT32 SELF_nbDataLength = SELF_MDLDataSize;									// 单个NET_BUFFER的datalength
	UINT32 SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;					// MAC帧头加IP首部的长度（多数情况下固定，但IP首部可能长度不一）
	// 确定分片数量
	UINT32 totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	MaxFragmentNum = (totalPayloadLength%SELF_MTUpayloadLen) > 0 ? (totalPayloadLength/SELF_MTUpayloadLen +1): totalPayloadLength / SELF_MTUpayloadLen; 
	// 当前NB中还需要拷贝的payload长度
	remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
	///////////////// 对第一块的NB，获取其头部信息，并做一些变量赋值 --end /////////////////////////////////////////////////////////////

	////////////////  MDL相关代码，只是为了构造NBL时使用FwpsAllocateNetBufferAndNetBufferList函数，函数需要手动构造MDL  --begin/////////
	// PMDL!!!!!!!!!!!内存释放问题待考虑
	PMDL pmdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(PMDL), CLONE_DATA_POOL_TAG);
	if (!pmdl)
		return FALSE;
	// 我们申请的这片DataPoolforMdl空间，就是用来存放packetdata的，
	DataPoolforMdl = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SELF_MDLDataSize, CLONE_DATA_POOL_TAG);	//分配一个足够的空间
	if (!DataPoolforMdl) {
		return FALSE;
	}
	RtlZeroMemory(DataPoolforMdl, SELF_MDLDataSize);
	pmdl = IoAllocateMdl(DataPoolforMdl, SELF_MDLDataSize, FALSE, FALSE, NULL);
	MmBuildMdlForNonPagedPool(pmdl);
	/////////////////	MDL相关代码	--end	////////////////////////////////////////////////////////////////////////////////////////////
	
	///////////////// 在如下for循环中进行第一块NB的处理，因为第一块NB涉及到NBL的构造，所以单独处理会更清晰 --begin /////////////////////
	for (UINT i = 0; i < MaxFragmentNum; i++)
	{
		if (i == 0)
		{
			status = FwpsAllocateNetBufferAndNetBufferList(nblPoolHandle, 0, 0, pmdl, 0, SELF_MDLDataSize, pCopyLayerdata);
			if (!NT_SUCCESS(status))
				return FALSE;
			PNET_BUFFER tmpnb = NET_BUFFER_LIST_FIRST_NB(*pCopyLayerdata);	//取第一个NB
			
			bytestocopy = SELF_MTUandMACSize;	// 需要copy MAC头部、IP头部、能整除8的payload长
			DestionationOffset = 0;				// DestionationOffset=0,SourceOffset=0
			SourceOffset = 0;
			NdisCopyFromNetBufferToNetBuffer(tmpnb, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)
			{
				// 拷贝错误，释放并返回
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
			// 如果当前数据包没有被分片，那么FragmentOffset应该设置0，
			// 如果当前数据包已经被分片了，FragmentOffset是原始的nbIP_FragmentOffset
			// 而flag则一定设置为001
			tmpFlags = 0b00100000;
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, SELF_MTUDataLen, tmpFlags, nbIP_FragmentOffset);

			// MAC填充
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
			// 当i!=0，此时已经处理好第一个分片
			// 通过Allocate配合Retreat，得到待有适当数据长度的MDL的NB
			PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
			status = NdisRetreatNetBufferDataStart(newNB, SELF_nbDataLength, 0, 0);
			if (!NT_SUCCESS(status)) 
				return FALSE;

			// 先把MAC首部和IP首部复制到对应位置
			bytestocopy = SELF_MACHandIPHLen;		// 需要复制首部需要14+iphlen字节
			DestionationOffset = 0;					// currentoffset象征性设置为2
			SourceOffset = 0;						// 从nb的起始位置开始复制
			NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// 判断复制是否成功
				return FALSE;

			// 复制完首部后，开始复制此分片的data
			bytestocopy = remainDataLen > SELF_MTUpayloadLen ? SELF_MTUpayloadLen : remainDataLen;
			DestionationOffset = SELF_MACHandIPHLen;					// des：跳过目的NB的TCP和IP首部
			SourceOffset = SELF_MACHandIPHLen + i * SELF_MTUpayloadLen;	// src：跳过源NB的首部和已经复制过的payload
			NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
			if (bytescopied != bytestocopy)			// 判断复制是否成功
				return FALSE;

			// 复制完成后设置nb的datalength和CurrentMdl->ByteCount
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
				tmpFlags = 0b00100000;	// 最后一片之前的flags必须是001
			else
				tmpFlags = nbIP_Flags;	// 最后一片的flags应该维持初始的flags
			updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, tmpTotalLen, tmpFlags, FragmentOffset);
			
			// MAC填充
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

	///////////////////进行第一块NB的处理 --end ////////////////////////////////////////////////////////////////////////////////////////

	///////////////// 处理完第一个NB后，单独进行后续NB的处理 --begin////////////////////////////////////////////////////////////////////
	if (remainDataLen != 0){
		return FALSE;		// 如果remainDataLen不是0，说明处理失败
	}
	else {	
		// 正确处理完第一个NB后，着手处理后面的NB，这种情况一般来说不多见，
		// 但是如果我们ping一个大于1472的数据包，一个NBL就会有多个NB
		nb = NET_BUFFER_NEXT_NB(nb);
		if (nb == NULL)
			return TRUE;

		// 此时我们有额外的NB需要处理，进入while循环
		while (nb)
		{
			BOOLEAN StraightCopyFlag = FALSE;
			currentMdlStart = MmGetSystemAddressForMdlSafe(NET_BUFFER_CURRENT_MDL(nb), NormalPagePriority);
			NetBufferData = (PUCHAR)currentMdlStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb);

			if (!(NetBufferData[12] == 0x08 && NetBufferData[13] == 0x00)) {
				StraightCopyFlag = TRUE;		// 这种情况几乎见不到，但是理论上我们也能处理，直接copy NB.datalength长的数据过去就可以
			}
			else {
				IPV4_HEADER_INIT(ipHeaderInfo, NetBufferData + 14);	// 只有IPV4协议的，才会进入初始化IPH
				if (ipHeaderInfo->TotalLength <= randomMTU)
					StraightCopyFlag = TRUE;	// 如果IP包的长度不足SELF_MTU,同样也是直接复制
			}	
			if (StraightCopyFlag)
			{
				// 通过Allocate配合Retreat，得到带有适当长度MDL的NB
				PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
				status = NdisRetreatNetBufferDataStart(newNB, nb->DataLength, 0, 0);
				if (!NT_SUCCESS(status))
					return FALSE;

				// 先把MAC首部和IP首部复制到对应位置
				bytestocopy = nb->DataLength;			// 需要复制NB的所有data
				DestionationOffset = 0;					// 设置为0
				SourceOffset = 0;						// 从nb的起始位置开始复制
				NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
				if (bytescopied != bytestocopy)			// 判断复制是否成功
					return FALSE;

				newNB->DataLength = nb->DataLength;
				newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
				remainDataLen = 0;

				// 经过测试，这里要我们自己填写，直接复制之后，IPcheck字段为0，但是wireshark抓包看到的不是0，
				// 可能是网卡会在最后检查IPcheck是否为0，如果为0会自动计算，但是我们自己构造的NBL，网卡没有为我们计算check
				if (ipHeaderInfo->TotalLength <= randomMTU) {
					// get iph
					PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
					if (!tmpMdlStart)
						return FALSE;
					PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;
					UINT16 checksum = GetIpCheckSum(ipHeader, ipHeaderInfo->HeaderLength);	// 要检验头部check能否算对
					ipHeader[10] = *(((PUCHAR)(&checksum)) + 1);
					ipHeader[11] = *(((PUCHAR)(&checksum)));
				}

				NET_BUFFER_NEXT_NB(currentNB) = newNB;
				currentNB = NET_BUFFER_NEXT_NB(currentNB);

				nb = NET_BUFFER_NEXT_NB(nb);			
				continue;		// 离开本次while循环
			}
			else {	// StraightCopyFlag为false，意味当前NB需要进行IP分片
				if (ipHeaderInfo->Flags == 0 || ipHeaderInfo->Flags == 2)		// 如果原IP数据包不允许分片即DF位=1，我们就手动置DF为0
					nbIP_Flags = 0b00000000;		// 源 IP flags
				else if (ipHeaderInfo->Flags == 1)								
					nbIP_Flags = 0b00100000;
				else
					return FALSE; // IP数据包Flags只有三种情况，其他情况不做处理

				nbIP_FragmentOffset = ipHeaderInfo->FragmentOffset;

				SELF_MTUpayloadLen = (randomMTU - ipHeaderInfo->HeaderLength) & 0xFFF8;	// 单个IP数据包，除去IP首部后的payload长度.因为分片的字节偏移必须是8的整数倍
				SELF_MTUDataLen = SELF_MTUpayloadLen + ipHeaderInfo->HeaderLength;		// 单个IP数据包，包括IP首部的总长度
				SELF_MTUandMACSize = SELF_MTUDataLen + 14;								// 单个IP数据包，包括IP首部和MAC帧头的长度
				SELF_MDLDataSize = SELF_MTUandMACSize + 0x20;							// 单个MDL的最小容量（留有0x20的冗余）
				SELF_nbDataLength = SELF_MDLDataSize;									// 单个NET_BUFFER的datalength
				SELF_MACHandIPHLen = 14 + ipHeaderInfo->HeaderLength;					// MAC帧头加IP首部的长度（多数情况下固定，但IP首部可能长度不一）
				// 确定分片数量
				totalPayloadLength = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;
				MaxFragmentNum = (totalPayloadLength % SELF_MTUpayloadLen) > 0 ? (totalPayloadLength / SELF_MTUpayloadLen + 1) : totalPayloadLength / SELF_MTUpayloadLen;
				// 当前NB中还需要拷贝的payload长度(不包括MAC头部和IP头部!!!!!)
				remainDataLen = ipHeaderInfo->TotalLength - ipHeaderInfo->HeaderLength;

				for (UINT i = 0; i < MaxFragmentNum; i++) {
					// 通过Allocate配合Retreat，得到带有适当长度MDL的NB
					PNET_BUFFER newNB = NdisAllocateNetBufferMdlAndData(nbPoolHandle);
					status = NdisRetreatNetBufferDataStart(newNB, SELF_nbDataLength, 0, 0);
					if (!NT_SUCCESS(status))
						return FALSE;

					if (i == 0) {	// 此处也要考虑第一个分片单独情况
						bytestocopy = SELF_MTUandMACSize;	// 需要copy MAC头部、IP头部外加能整除8的payload长
						DestionationOffset = 0;				//DestionationOffset=0,SourceOffset=0
						SourceOffset = 0;
						NdisCopyFromNetBufferToNetBuffer(newNB, DestionationOffset, bytestocopy, nb, SourceOffset, &bytescopied);
						if (bytescopied != bytestocopy)			// 判断复制是否成功
							return FALSE;
						newNB->DataLength = SELF_MTUandMACSize;
						newNB->CurrentMdl->ByteCount = newNB->DataLength + newNB->CurrentMdlOffset;
						remainDataLen -= SELF_MTUpayloadLen;	// 注意，第一个分片携带的数据长度是SELF_MTUpayloadLen

						// get ipH
						PVOID tmpMdlStart = MmGetSystemAddressForMdlSafe(newNB->CurrentMdl, NormalPagePriority);
						if (!tmpMdlStart)
							return FALSE;
						PUCHAR ipHeader = (PUCHAR)tmpMdlStart + newNB->CurrentMdlOffset + 14;

						// update ipH
						// 如果当前数据包没有被分片，那么FragmentOffset应该设置0，
						// 如果当前数据包已经被分片了，FragmentOffset是原始的nbIP_FragmentOffset
						// 而flag则一定设置为001
						UCHAR tmpFlags = 0b00100000;
						updateIPHeader(ipHeader, ipHeaderInfo->HeaderLength, SELF_MTUDataLen, tmpFlags, nbIP_FragmentOffset);
					}

					