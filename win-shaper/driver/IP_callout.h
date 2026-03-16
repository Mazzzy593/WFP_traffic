#pragma once

BOOLEAN TCPandIPfragment(_In_ const FWPS_INCOMING_VALUES* inFixedValues,   // 经过包装的数据包的相关信息， 有layer ID, source and destination addresses
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,   // 经过包装的数据信息，interface index, timestamps
	_Inout_opt_ void* layerData,
	BOOLEAN outbound, // 标志位
	_In_ HANDLE injection_handle);

VOID updateTCPSeqNumber(PUCHAR tcpPacket, UINT alreadyCopied);

void updateTCPchecksum(PUCHAR pIPHeader, PUCHAR pTCPHeader, PUCHAR pPayload, UINT TCPHeaderLen, UINT PayloadLen);