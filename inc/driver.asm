;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;


;-------------------------------------- driver.asm ----------------------------------------;

; ported from C version include WINDDK 2003
; written in 15-sept-2007 by anvie

; ------- MACRO ------- ;

.data?

; IO driver Control code ported form DDK C wdm.h to MASM macro format by anvie
CTL_CODE MACRO DeviceType, Function, Method, Access

	EXITM <((DeviceType) shl 16) or \
	 		((Access) shl 14) or \
	 		((Function) shl 2) or \
	 		(Method)>
ENDM

; ------- C define auto generated in asm by anvie ------- ; 
FILE_DEVICE_UNKNOWN             equ 00000022h
FILE_DEVICE_BEEP                equ 00000001h
FILE_DEVICE_CD_ROM              equ 00000002h
FILE_DEVICE_CD_ROM_FILE_SYSTEM  equ 00000003h
FILE_DEVICE_CONTROLLER          equ 00000004h
FILE_DEVICE_DATALINK            equ 00000005h
FILE_DEVICE_DFS                 equ 00000006h
FILE_DEVICE_DISK                equ 00000007h
FILE_DEVICE_DISK_FILE_SYSTEM    equ 00000008h
FILE_DEVICE_FILE_SYSTEM         equ 00000009h
FILE_DEVICE_INPORT_PORT         equ 0000000ah
FILE_DEVICE_KEYBOARD            equ 0000000bh
FILE_DEVICE_MAILSLOT            equ 0000000ch
FILE_DEVICE_MIDI_IN             equ 0000000dh
FILE_DEVICE_MIDI_OUT            equ 0000000eh
FILE_DEVICE_MOUSE               equ 0000000fh
FILE_DEVICE_MULTI_UNC_PROVIDER  equ 00000010h
FILE_DEVICE_NAMED_PIPE          equ 00000011h
FILE_DEVICE_NETWORK             equ 00000012h
FILE_DEVICE_NETWORK_BROWSER     equ 00000013h
FILE_DEVICE_NETWORK_FILE_SYSTEM equ 00000014h
FILE_DEVICE_NULL                equ 00000015h
FILE_DEVICE_PARALLEL_PORT       equ 00000016h
FILE_DEVICE_PHYSICAL_NETCARD    equ 00000017h
FILE_DEVICE_PRINTER             equ 00000018h
FILE_DEVICE_SCANNER             equ 00000019h
FILE_DEVICE_SERIAL_MOUSE_PORT   equ 0000001ah
FILE_DEVICE_SERIAL_PORT         equ 0000001bh
FILE_DEVICE_SCREEN              equ 0000001ch
FILE_DEVICE_SOUND               equ 0000001dh
FILE_DEVICE_STREAMS             equ 0000001eh
FILE_DEVICE_TAPE                equ 0000001fh
FILE_DEVICE_TAPE_FILE_SYSTEM    equ 00000020h
FILE_DEVICE_TRANSPORT           equ 00000021h
FILE_DEVICE_UNKNOWN             equ 00000022h
FILE_DEVICE_VIDEO               equ 00000023h
FILE_DEVICE_VIRTUAL_DISK        equ 00000024h
FILE_DEVICE_WAVE_IN             equ 00000025h
FILE_DEVICE_WAVE_OUT            equ 00000026h
FILE_DEVICE_8042_PORT           equ 00000027h
FILE_DEVICE_NETWORK_REDIRECTOR  equ 00000028h
FILE_DEVICE_BATTERY             equ 00000029h
FILE_DEVICE_BUS_EXTENDER        equ 0000002ah
FILE_DEVICE_MODEM               equ 0000002bh
FILE_DEVICE_VDM                 equ 0000002ch
FILE_DEVICE_MASS_STORAGE        equ 0000002dh
FILE_DEVICE_SMB                 equ 0000002eh
FILE_DEVICE_KS                  equ 0000002fh
FILE_DEVICE_CHANGER             equ 00000030h
FILE_DEVICE_SMARTCARD           equ 00000031h
FILE_DEVICE_ACPI                equ 00000032h
FILE_DEVICE_DVD                 equ 00000033h
FILE_DEVICE_FULLSCREEN_VIDEO    equ 00000034h
FILE_DEVICE_DFS_FILE_SYSTEM     equ 00000035h
FILE_DEVICE_DFS_VOLUME          equ 00000036h
FILE_DEVICE_SERENUM             equ 00000037h
FILE_DEVICE_TERMSRV             equ 00000038h
FILE_DEVICE_KSEC                equ 00000039h
FILE_DEVICE_FIPS				equ 0000003Ah

METHOD_BUFFERED                 equ 0
METHOD_IN_DIRECT                equ 1
METHOD_OUT_DIRECT               equ 2
METHOD_NEITHER                  equ 3

FILE_READ_DATA            		equ 0001h
FILE_LIST_DIRECTORY       		equ 0001h

FILE_WRITE_DATA           		equ 0002h
FILE_ADD_FILE             		equ 0002h

FILE_APPEND_DATA          		equ 0004h
FILE_ADD_SUBDIRECTORY     		equ 0004h
FILE_CREATE_PIPE_INSTANCE 		equ 0004h


DRVCOMM_BUFFER struct
	status dd ?
DRVCOMM_BUFFER ends

.code












