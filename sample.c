#include <ntddk.h>
#include "..\\common\\intface.H"

#ifdef _WIN64
void genint(); // assembly code
#endif

typedef struct _DEVICE_EXTENSION
{
	UNICODE_STRING SymbolicLinkName; // 얻어지는 이름을 보관함

	PDEVICE_OBJECT  pNextLayerDeviceObject;

	ULONG Count;
	CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[MAX_RES_COUNT];

	// 인터럽트 서비스 루틴을 연결하면 준비되는 필드
	PKINTERRUPT pInterruptObject;

	// 이벤트는 반드시 하나만 등록이 되어야 함
	// 응용 프로그램과 인터럽트를 연결하는 이벤트(Kernel Object)
	void* pEventObject; 

	// 이벤트를 해제하기 위해 관리하는 참조수와 스핀락
	LONG  CreateReferenceCount;
	KSPIN_LOCK ReferenceSpinLock;

	// 인터럽트를 발생하기 위해 정의한 필드
	unsigned char IntVector;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;


void SampleDriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
}

//인터럽트 핸들러
BOOLEAN 
InterruptHandler(
	PKINTERRUPT Interrupt,
	PVOID ServiceContext
)
{
	PDEVICE_OBJECT pDeviceObject = NULL;

	UNREFERENCED_PARAMETER(Interrupt);

	pDeviceObject = ServiceContext;

	// DPC인터럽트를 요청함
	IoRequestDpc(pDeviceObject, NULL, NULL);

	return TRUE;
}

//인터럽트와 관련된 DPC 루틴
VOID
InterruptDpcRoutine(
	PKDPC Dpc,
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
)
{
	KIRQL OldIrql;
	PDEVICE_EXTENSION pDeviceExtension = NULL;

	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(Context);

	//DpcRoutine에서 다음과 같은 동기화작업을 하지 않으면 CloseDispatch 부분과 동기화 문제가 발생할 수도 있다.
	//즉 응용프로그램이 종료될 때, 동기화 이슈로 인한 BSOD가 발생할 여지가 있으므로 반드시 동기화를 해야한다. 
	pDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	KeAcquireSpinLock(&pDeviceExtension->ReferenceSpinLock, &OldIrql);
	if (pDeviceExtension->pEventObject)
	{
		KeSetEvent(pDeviceExtension->pEventObject, 0, FALSE);
	}
	KeReleaseSpinLock(&pDeviceExtension->ReferenceSpinLock, OldIrql);

}
NTSTATUS SampleDriverAddDevice(PDRIVER_OBJECT pDrvObj, PDEVICE_OBJECT pPhysicalDeviceObject)
{
	PDEVICE_OBJECT pDeviceObject = NULL;
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	ntStatus = IoCreateDevice(
		pDrvObj,
		sizeof(DEVICE_EXTENSION),
		NULL, // DeviceObject의 이름을 주지 않습니다. 
		// 왜냐하면, pPhysicalDeviceObject의 이름이 대신 사용되기 때문입니다
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDeviceObject
	);
	if (!NT_SUCCESS(ntStatus))
	{
		goto exit;
	}

	// 생성된 DeviceObject에서 DeviceExtension 포인터를 가져옵니다
	pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	memset(pDeviceExtension, 0, sizeof(PDEVICE_EXTENSION));

	KeInitializeSpinLock(&pDeviceExtension->ReferenceSpinLock);

	// DPC를 준비합니다
	IoInitializeDpcRequest(pDeviceObject, InterruptDpcRoutine);

	// PhysicalDeviceObject로 부터 시작된 현재의 DeviceStack의 최상위로 DeviceObject를 올립니다
	// IoAttachDeviceToDeviceStack() 함수의 리턴값은 우리의 DeviceObject 바로 아래의 DeviceObject를 나타냅니다
	pDeviceExtension->pNextLayerDeviceObject =
		IoAttachDeviceToDeviceStack(pDeviceObject, pPhysicalDeviceObject);

	// DeviceObject 위로 다른 DeviceObject가 올라가는 것을 허용합니다
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// GUID를 사용해서 심볼릭이름을 얻어옵니다
	ntStatus = IoRegisterDeviceInterface(
		pPhysicalDeviceObject,
		(struct _GUID*)&SampleGuid,
		NULL,
		&pDeviceExtension->SymbolicLinkName
	);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		goto exit;
	}

	ntStatus = STATUS_SUCCESS;

exit:
	return ntStatus;
}

// 동기식 IRP를 다루기 위한 MyCompletion
NTSTATUS MyCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);
	// IRP가 완료되었음을 알림
	KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
	// IRP를 그대로 반환
	return STATUS_MORE_PROCESSING_REQUIRED;	
}

NTSTATUS SampleDriverCreateDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	KIRQL OldIrql;
	UNREFERENCED_PARAMETER(pDevObj);

	pDeviceExtension = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	KeAcquireSpinLock(&pDeviceExtension->ReferenceSpinLock, &OldIrql);

	pDeviceExtension->CreateReferenceCount++;

	KeReleaseSpinLock(&pDeviceExtension->ReferenceSpinLock, OldIrql);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS SampleDriverCloseDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	KIRQL OldIrql;
	UNREFERENCED_PARAMETER(pDevObj);

	pDeviceExtension = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	KeAcquireSpinLock(&pDeviceExtension->ReferenceSpinLock, &OldIrql);
	pDeviceExtension->CreateReferenceCount--;
	if (pDeviceExtension->CreateReferenceCount == 0)
	{
		if (pDeviceExtension->pEventObject)
		{
			ObDereferenceObject(pDeviceExtension->pEventObject);
			pDeviceExtension->pEventObject = NULL;
		}
	}

	KeReleaseSpinLock(&pDeviceExtension->ReferenceSpinLock, OldIrql);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS; 

}

NTSTATUS SampleDriverDeviceIoControlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	NTSTATUS ntStatus = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pStack = NULL;

	// 보통 아래와 같이 정의해서 사용하는 것이 편리함
	ULONG dwIoctlCode;
	ULONG InputBufferLength;
	ULONG OutputBufferLength;
	PVOID pSystemBuffer = NULL;
	ULONG_PTR Information = 0;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	pDeviceExtension = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	dwIoctlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	InputBufferLength = pStack->Parameters.DeviceIoControl.InputBufferLength;	
	OutputBufferLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;		
	pSystemBuffer = pIrp->AssociatedIrp.SystemBuffer;	

	switch (dwIoctlCode)
	{
	case IOCTL_PNPGENERIC_GET_RESOURCE:
	{
		IOCTL_PNPGENERIC_GET_RESOURCE_INFO* pOutputBuffer;
		pOutputBuffer = pSystemBuffer;

		// 시스템 버퍼로 부터 받은 데이터가 없는 경우 예외 처리
		if (pOutputBuffer == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}
		// 읽어 온 데이터가 IOCTL_PNPGENERIC_GET_RESOURCE_INFO 크기와 다른 경우 예외 처리
		if (OutputBufferLength != sizeof(IOCTL_PNPGENERIC_GET_RESOURCE_INFO))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}

		// 요청 처리
		Information = pDeviceExtension->Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
		pOutputBuffer->Count = pDeviceExtension->Count;
		memcpy(&pOutputBuffer->PartialDescriptors[0],
			&pDeviceExtension->PartialDescriptors[0],
			Information);

		ntStatus = STATUS_SUCCESS;
		break;

	}


	case IOCTL_PNPGENERIC_MEMORY_READ:
	{
		IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO* pInfo = pSystemBuffer;

		//1. 유효성 검사 (입력 버퍼와 출력 버퍼 크기 확인)
		if (pInfo == NULL || InputBufferLength != sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO)
			|| OutputBufferLength != sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}

		PHYSICAL_ADDRESS TargetPhysicalAddress = pInfo->PhysicalAddress; // 읽고 쓰기 전에, IOCTL_PNPGENERIC_GET_RESOURCE_INFO에서 자원으로 할당된 물리 주소를 얻었으므로, 그 주소를 사용하게 된다. 
		TargetPhysicalAddress.QuadPart += pInfo->Offset; // 출발점이 어디인가를 정한다. Application code 쪽에서 0으로 할당했다. 즉, 자원 시작점부터 읽겠다는 의미

		PVOID pMappedAddr = MmMapIoSpace(
			TargetPhysicalAddress,
			(SIZE_T)pInfo->Length,
			MmNonCached
		);

		if (pMappedAddr)
		{
			// 하드웨어 -> 시스템 버퍼의 Buffer 배열로 복사
			RtlCopyMemory(
				pInfo->Buffer,
				pMappedAddr,
				(SIZE_T)pInfo->Length
			);

			MmUnmapIoSpace(
				pMappedAddr,
				(SIZE_T)pInfo->Length
			);

			Information = sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO);
			ntStatus = STATUS_SUCCESS;
		}

		else
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		}

		break;
		
	}

	case IOCTL_PNPGENERIC_MEMORY_WRITE:
	{
		IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO* pInfo = pSystemBuffer;
		//1. 유효성 검사 (입력 버퍼와 출력 버퍼 크기 확인)
		if (pInfo == NULL || InputBufferLength != sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO)
			|| OutputBufferLength != sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}
		PHYSICAL_ADDRESS TargetPhysicalAddress = pInfo->PhysicalAddress; // 읽고 쓰기 전에, IOCTL_PNPGENERIC_GET_RESOURCE_INFO에서 자원으로 할당된 물리 주소를 얻었으므로, 그 주소를 사용하게 된다. 
		TargetPhysicalAddress.QuadPart += pInfo->Offset; // 출발점이 어디인가를 정한다. Application code 쪽에서 0으로 할당했다. 즉, 자원 시작점부터 읽겠다는 의미
		PVOID pMappedAddr = MmMapIoSpace(
			TargetPhysicalAddress,
			(SIZE_T)pInfo->Length,
			MmNonCached
		);
		if (pMappedAddr)
		{
			// 시스템 버퍼의 Buffer 배열 -> 하드웨어로 복사
			RtlCopyMemory(
				pMappedAddr,
				pInfo->Buffer,
				(SIZE_T)pInfo->Length
			);
			MmUnmapIoSpace(
				pMappedAddr,
				(SIZE_T)pInfo->Length
			);
			Information = sizeof(IOCTL_PNPGENERIC_MEMORY_ACCESS_INFO);
			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		}
		break;
	}

	case IOCTL_PNPGENERIC_CONNECT_INTERRUPT:
	{
		KIRQL OldIrql; 
		void* pEvent = NULL; 

		//이 부분은 응용프로그램과 주고 받은 입출력버퍼를 정의함
		IOCTL_PNPGENERIC_CONNECT_INTERRUPT_INFO* pInputBuffer;

		pInputBuffer = pSystemBuffer;

		//전달되는 파라미터의 유효성을 확인함
		if (pInputBuffer == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}

		if (InputBufferLength != sizeof(IOCTL_PNPGENERIC_CONNECT_INTERRUPT_INFO))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto exit;
		}

		ntStatus = ObReferenceObjectByHandle(
			pInputBuffer->hEvent,
			0,
			NULL,
			KernelMode,
			&pEvent,
			NULL
		);

		if (!NT_SUCCESS(ntStatus))
			goto exit;

		KeAcquireSpinLock(&pDeviceExtension->ReferenceSpinLock, &OldIrql);
		//이미 등록된 이벤트가 있다면 새로 등록함
		if (pDeviceExtension->pEventObject)
		{
			ObDereferenceObject(pDeviceExtension->pEventObject);
			pDeviceExtension->pEventObject = NULL;
		}
		pDeviceExtension->pEventObject = pEvent;

		KeReleaseSpinLock(&pDeviceExtension->ReferenceSpinLock, OldIrql);
		ntStatus = STATUS_SUCCESS;
		break;


	}

	case IOCTL_PNPGENERIC_DISCONNECT_INTERRUPT:
	{
		KIRQL OldIrql;

		KeAcquireSpinLock(&pDeviceExtension->ReferenceSpinLock, &OldIrql);

		if (pDeviceExtension->pEventObject)
		{
			ObDereferenceObject(pDeviceExtension->pEventObject);
			pDeviceExtension->pEventObject = NULL;
		}
		KeReleaseSpinLock(&pDeviceExtension->ReferenceSpinLock, OldIrql);
		ntStatus = STATUS_SUCCESS;
		break;
	}

	// 특별히 추가된 명령어로서, 인터럽트를 흉내내는 IOCTL 이다.
	case IOCTL_PNPGENERIC_GENERATE_INTERRUPT:
	{
		if (pDeviceExtension->IntVector == 0)
			break;

		//x64에서만 지원하도록 함
#ifndef _WIN64
		break;
#endif // _WIN64
		//어셈블리어 코드의 Operand 부분을 변경해야 한다.
		//InterruptVector 또한 하드웨어 자원(Resources)이므로 드라이버가 어느 디바이스 위에 올라갈 것이냐에 따라 벡터 번호는 달라지기 마련이다.
		//사정이 그렇다면, 런타임 전에 벡터 번호를 알아내어 MASM(Microsoft Assembly)으로 하드 코딩하는 방식을 고민해 볼 수 있겠는데, 아쉽게도 CODE 영역은 Read Only이다.
		//즉, genint의 물리 주소와 매핑된 커널 가상메모리 공간을 이용해 고유한 인터럽트 벡터 번호를 Write 해야한다. 
		//그 로직이 아래의 코드로 구현되어 있다.

		{
			void* pFunctionAddress;
			PHYSICAL_ADDRESS FunctionAddressPhysicalAddress;
			unsigned char* pNewVirtualAddressForWrite;
			pFunctionAddress = (void*)genint;
			FunctionAddressPhysicalAddress = MmGetPhysicalAddress(pFunctionAddress);
			pNewVirtualAddressForWrite = MmMapIoSpace(
				FunctionAddressPhysicalAddress,
				3,
				MmNonCached
			);
			//pNewVirtualAddressForWrite[0] = int
			//pNewVirtualAddressForWrite[1] = xx
			//pNewVirtualAddressForWrite[2] = ret
			pNewVirtualAddressForWrite[1] = pDeviceExtension->IntVector;
			MmUnmapIoSpace(pNewVirtualAddressForWrite, 3);
		}

		//인터럽트 발생시킨다. 
		genint();
		
		ntStatus = STATUS_SUCCESS;
		break;

	}

	default:
		break;
}



exit:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = Information;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
	
}

NTSTATUS SampleDriverPnPDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	PIO_STACK_LOCATION pStack = NULL;
	PDEVICE_OBJECT pNextLayerDeviceObject = NULL;
	NTSTATUS ntStatus;
	KEVENT Event; // 후처리에 사용하려는 이벤트
	ULONG Count;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	pDeviceExtension = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pNextLayerDeviceObject = pDeviceExtension->pNextLayerDeviceObject;
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (pStack->MinorFunction)
	{
	case IRP_MN_START_DEVICE:
		// 후처리 로직으로 구현되어야 함
		IoCopyCurrentIrpStackLocationToNext(pIrp); // 우선 난 모르겠고, 아래 드라이버로 넘긴 후 결과값을 확인받는다.
		IoSetCompletionRoutine(
			pIrp,
			MyCompletion,
			&Event,
			TRUE,
			TRUE,
			TRUE
		);

		IoCallDriver(pNextLayerDeviceObject, pIrp);

		KeWaitForSingleObject(
			&Event,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		if (NT_SUCCESS(pIrp->IoStatus.Status))
		{
			{
				PCM_RESOURCE_LIST pCmResourceList;
				PCM_PARTIAL_RESOURCE_LIST pCmPartialResourceList;

			    // 심볼릭 이름이 사용되도록 허가함 ( at CreateFile() )
				IoSetDeviceInterfaceState(&pDeviceExtension->SymbolicLinkName, TRUE);

				pCmResourceList = (PCM_RESOURCE_LIST)pStack->Parameters.StartDevice.AllocatedResourcesTranslated;

				if (pCmResourceList == NULL)
				{
					goto exit_start_device;
				}

				pCmPartialResourceList = (PCM_PARTIAL_RESOURCE_LIST)&pCmResourceList->List[0].PartialResourceList;
				pDeviceExtension->Count = pCmPartialResourceList->Count;
				memcpy(
					&pDeviceExtension->PartialDescriptors[0],
					&pCmPartialResourceList->PartialDescriptors[0],
					sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * pCmPartialResourceList->Count
				);
			}
		}

		//리소스 중 인터럽트 리소스가 있다면, 인터럽트핸들러를 설치함
		for (Count = 0; Count < pDeviceExtension->Count; Count++)
		{
			if (pDeviceExtension->PartialDescriptors[Count].Type == CmResourceTypeInterrupt)
			{
				/*
				pDeviceExtension->PartialDescriptors[Count].u.Interrupt.level;
				pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Vector;
				pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Affinity;
				*/

				ntStatus = IoConnectInterrupt(
					&pDeviceExtension->pInterruptObject,
					InterruptHandler,
					pDevObj,
					NULL,
					pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Vector,
					(KIRQL)pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Level,
					(KIRQL)pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Level,
					LevelSensitive,
					TRUE,
					pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Affinity,
					FALSE);


				if (NT_SUCCESS(ntStatus))
				{
					pDeviceExtension->IntVector =
						(unsigned char)pDeviceExtension->PartialDescriptors[Count].u.Interrupt.Vector;
				}
				break;
			}
		}
exit_start_device:
		ntStatus = pIrp->IoStatus.Status;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return ntStatus;


	case IRP_MN_REMOVE_DEVICE:
		//선처리 로직
		//
		//
	

		//사용 중이었던 인터럽트 서비스 루틴을 해제한다.
		if (pDeviceExtension->pInterruptObject)
		{
			IoDisconnectInterrupt(pDeviceExtension->pInterruptObject);
			pDeviceExtension->pInterruptObject = NULL;
		}

		// 심볼릭 이름이 사용되지 않도록 금지함.
		IoSetDeviceInterfaceState(&pDeviceExtension->SymbolicLinkName, FALSE);
		// 심볼릭 이름을 메모리에서 제거함.
		RtlFreeUnicodeString(&pDeviceExtension->SymbolicLinkName);

		IoDetachDevice(pNextLayerDeviceObject);
		// 디바이스 스택으로부터 연결을 해제함.

		IoDeleteDevice(pDevObj);
		// 나의 DeviceObject를 제거함.
		break; 

	}

	IoSkipCurrentIrpStackLocation(pIrp);	
	return IoCallDriver(pNextLayerDeviceObject, pIrp);

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	pDrvObj->MajorFunction[IRP_MJ_PNP] = SampleDriverPnPDispatch;
	pDrvObj->MajorFunction[IRP_MJ_CREATE] = SampleDriverCreateDispatch;
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = SampleDriverCloseDispatch;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SampleDriverDeviceIoControlDispatch;

	pDrvObj->DriverExtension->AddDevice = SampleDriverAddDevice;
	pDrvObj->DriverUnload = SampleDriverUnload;

	return STATUS_SUCCESS;
}
