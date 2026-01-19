#include <stdio.h>
#include <windows.h>
#include <SetupAPI.h>
#include <reshub.h>
#include <initguid.h>
#define MAX_CONNECTIONID_COUNT   (2)
// 하나의 Peripheral 장치가 사용하는 ConnectionId의 최대개수를 정의함

#include "wdk_header_for_app.H"
// WDK.H 에 포함된 내용중 응용프로그램에서 사용할 내용을 위해 추가합니다

#include "..\\common\\intface.h"
// IOCTL 정의를 위해서 추가합니다

#pragma comment(lib, "user32.lib") // Win32 API MessageBox()호출을 위하여
#pragma comment(lib, "setupapi.lib")

// 이름을 구해오는 방법을 함수로 구현한다.
// Setup API 함수를 사용하는 모습을 확인할 수 있다.
// 추후에 복붙개념으로 이용해도 좋다!

#define MAX_CONNECTION_COUNT (2)
//하나의 Peripheral 장치가 사용하는 ConnectionId의 최대 개수를 정의함


//이름을 구해오는 방법을 함수로 따로 구현한다.
//Setup AI 함수를 사용하는 방식을 잘 공부해둘 것

BOOLEAN GetDeviceStackName(struct _GUID* pGuid, WCHAR** ppDeviceName, int index)
{
	DWORD size;
	BOOLEAN bl;
	SP_INTERFACE_DEVICE_DATA interfaceData;
	PSP_INTERFACE_DEVICE_DETAIL_DATA pData;
	HDEVINFO Info = SetupDiGetClassDevs(pGuid, 0, 0, DIGCF_PRESENT | DIGCF_INTERFACEDEVICE); //현재 시스템에 있는 디바이스만 반환 + GUID 기반 탐색
	WCHAR* pDeviceName; 
	*ppDeviceName = (WCHAR*)0;

	if (Info == (HANDLE)-1)
		return FALSE;

	interfaceData.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

	bl = SetupDiEnumDeviceInterfaces(Info, 0, pGuid, index, &interfaceData);
	if (bl == FALSE)
		return bl;

	SetupDiGetDeviceInterfaceDetail(Info, &interfaceData, 0, 0, &size, 0);
	pData = (PSP_INTERFACE_DEVICE_DETAIL_DATA)malloc(size);
	if (!pData)
	{		
		return FALSE;
	}

	pData->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);
	SetupDiGetDeviceInterfaceDetail(Info, &interfaceData, pData, size, 0, 0);
	if (pData)
	{
		pDeviceName = (WCHAR*)malloc(wcslen(pData->DevicePath + 1) * sizeof(WCHAR));

		if (pDeviceName)
		{
			memset(pDeviceName, 0, wcslen(pData->DevicePath) * sizeof(WCHAR));
			wcscpy_s(pDeviceName, (sizeof(WCHAR) * wcslen(pData->DevicePath) + 1), pData->DevicePath);
		}
		free(pData);
	}
	SetupDiDestroyDeviceInfoList(Info);
}


void MakeDeviceNameFromConnectionId(WCHAR* pName, ULONG IdHighPart, ULONG IdLowPart)
{
	pName[0] = 0;
	swprintf_s(pName, MAX_PATH, L"\\\\.\\RESOSURCE_HUB\\%08x%08x", IdHighPart, IdLowPart);
}

BOOLEAN DoJobForPeripheral(HANDLE hDevice)
{
	BOOLEAN bRet = FALSE; 
	IOCTL_PNPGENERIC_GET_RESOURCE_INFO* pResourceInfo = { 0 , };
	PHYSICAL_ADDRESS MemoryResource = { 0, };
	DWORD dwRet; 
	ULONG Count;
	WCHAR DeviceNameFromConnectionId[MAX_CONNECTION_COUNT][MAX_PATH] = { 0, };
	int ConnectIdCount = 0;
	HANDLE hConnectionIdHandle = (HANDLE)-1;

	pResourceInfo = (IOCTL_PNPGENERIC_GET_RESOURCE_INFO*)malloc(sizeof(IOCTL_PNPGENERIC_GET_RESOURCE_INFO));
	if (pResourceInfo == NULL)
		goto exit;

	bRet = DeviceIoControl(
		hDevice,
		IOCTL_PNPGENERIC_GET_RESOURCE,
		NULL,
		0,
		pResourceInfo,
		sizeof(IOCTL_PNPGENERIC_GET_RESOURCE_INFO),
		&dwRet,
		NULL
	);
	if (bRet == FALSE)
		goto exit;

	printf("Resource Info\n");
	for (Count = 0; Count < pResourceInfo->Count; Count++)
	{
		switch (pResourceInfo->PartialDescriptors[Count].Type)
		{
		case CmResourceTypePort:		// IO Port 리소스
			printf("	[%02d] Type : CmResourceTypePort\n", Count);
			printf("		Start   : 0x%p\n", (void*)pResourceInfo->PartialDescriptors[Count].u.Port.Start.QuadPart);
			printf("		Length  : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Port.Length);
			break;
		case CmResourceTypeInterrupt:	// Interrupt 리소스
			printf("	[%02d] Type  : CmResourceTypeInterrupt\n", Count);
			printf("		Affinity : 0x%p\n", (void*)pResourceInfo->PartialDescriptors[Count].u.Interrupt.Affinity);
			printf("		Level    : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Interrupt.Level);
			printf("		Vector   : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Interrupt.Vector);
			break;
		case CmResourceTypeMemory:		// Memory 리소스
			printf("	[%02d] Type : CmResourceTypeMemory\n", Count);
			printf("		Start   : 0x%p\n", (void*)pResourceInfo->PartialDescriptors[Count].u.Memory.Start.QuadPart);
			printf("		Length  : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Memory.Length);
			MemoryResource.QuadPart = pResourceInfo->PartialDescriptors[Count].u.Memory.Start.QuadPart;
			break;
		case CmResourceTypeConnection:	// Connection 리소스
			printf("	[%02d] Type    : CmResourceTypeConnection\n", Count);
			printf("		IdHighPart : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Connection.IdHighPart);
			printf("		IdLowPart  : 0x%x\n", pResourceInfo->PartialDescriptors[Count].u.Connection.IdLowPart);

			MakeDeviceNameFromConnectionId(
				DeviceNameFromConnectionId[ConnectIdCount],
				pResourceInfo->PartialDescriptors[Count].u.Connection.IdHighPart,
				pResourceInfo->PartialDescriptors[Count].u.Connection.IdLowPart
			);
			// CreateFile()에 사용하는 이름을 준비합니다
			ConnectIdCount++;
			break;
		default:
			printf("	[%02d] Type : CmResourceTypeUnknown(0x%x)\n", Count, pResourceInfo->PartialDescriptors[Count].Type);
			continue; // 나머지 리소스는 관심이 없습니다
		}
	}

	// ConnectionId를 사용해서 생성한 이름을 사용해서 열기를 시도해봅니다
	for (Count = 0; Count < ConnectIdCount; Count++)
	{
		printf("DeviceNameFromConnectionId Name : %ws)\n", DeviceNameFromConnectionId[Count]);
		hConnectionIdHandle = CreateFile(
			DeviceNameFromConnectionId[Count],
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);
		// 열기를 시도합니다. 허용되었다면 열리게 되겠지요
		if (hConnectionIdHandle == (HANDLE)INVALID_HANDLE_VALUE)
		{
			printf("Fail!!, CreateFile DeviceNameFromConnectionId Name)\n");
			continue;
		}
		printf("Success!!, CreateFile DeviceNameFromConnectionId Name)\n");

		// 향후 통신을 해볼 수 있습니다
		//

		CloseHandle(hConnectionIdHandle);
	}

	bRet = TRUE;

exit:
	if (pResourceInfo)
		free(pResourceInfo);

	return bRet;
}

int main()
{
	WCHAR* pDeviceName = NULL;
	HANDLE hDevice = (HANDLE)INVALID_HANDLE_VALUE;
	BOOLEAN bRet = FALSE;
	int FoundIndex = 0;

	while (1)
	{
		bRet = GetDeviceStackName(
			(struct _GUID*)&SampleGuid,
			&pDeviceName,	// 심볼릭이름이 얻어집니다. 주의!!! 사용이 끝나면 해제해야 합니다
			FoundIndex); // 몇번째로 발견되는 디바이스인가...

		if (bRet == FALSE)
			break;

		hDevice = CreateFile(
			pDeviceName,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);
		// 열기를 시도합니다. 허용되었다면 열리게 되겠지요
		if (hDevice == (HANDLE)INVALID_HANDLE_VALUE)
		{
			printf("Open Fail!!, Symbolic Name = %ws\n", pDeviceName);
			free(pDeviceName);
			FoundIndex++;
			continue;
		}

		// 해당하는 장치와 연결합니다
		DoJobForPeripheral(hDevice);

		CloseHandle(hDevice);

		// 열린 디바이스의 이름(심볼릭)을 출력합니다
		printf("Symbolic Name = %ws\n", pDeviceName);
		free(pDeviceName);

		FoundIndex++;
	}
exit:
	MessageBox(0, L"Wait", L"CallDriver", MB_OK);
	return 0;
}
