
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
