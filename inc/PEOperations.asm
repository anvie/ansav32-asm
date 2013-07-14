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


; ------- PE helper ------- ;

IFNDEF	IMAGEHLP_INCLUDED_FILE
	IMAGEHLP_INCLUDED_FILE	equ 1
	include 	imagehlp.inc
	includelib 	imagehlp.lib
ENDIF

.code

align 16


Rva2Raw proc uses edx ebx iBase:DWORD,dwRVA:DWORD

	; ------- seh installation ------- ;
	SehBegin 	__r2r

	mov 	edx,iBase
	add 	edx,03Ch
	add 	dx,[edx]
	sub 	dx,03Ch
	
	invoke ImageRvaToSection,edx,iBase,dwRVA
	.if eax
		mov 	ebx,dwRVA
		xchg 	ebx,eax
		assume 	ebx:ptr IMAGE_SECTION_HEADER
		add 	eax,[ebx].PointerToRawData
		sub 	eax,[ebx].VirtualAddress
		assume 	ebx:nothing
	.else
		add 	eax,dwRVA
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__r2r
		ErrorDump 	"Rva2Raw",offset Rva2Raw,"peoperations.asm"
	SehEnd 		__r2r
	
	ret
Rva2Raw endp

align 16

Raw2Rva proc uses edx ebx sect:DWORD, dwRVA:DWORD


	mov ebx,sect
	mov eax,dwRVA
	assume ebx:ptr IMAGE_SECTION_HEADER
	add eax,[ebx].VirtualAddress
	sub eax,[ebx].PointerToRawData
	assume ebx:nothing

		
	ret

Raw2Rva endp

align 16

; returns aligned value
PEAlign PROC uses ecx edx, arnum : DWORD, alignto : DWORD

	mov ecx,alignto
	mov eax,arnum
	xor edx,edx
	div ecx
	cmp edx,0
	jz algn
	inc eax	
   algn:
   	mul ecx
	ret
PEAlign ENDP

align 16

SectionHeadPtr proc Num, lpFile: DWORD

        ; Num * 28h
        xor     edx, edx
        mov     eax, 28h ; obj table size
        mul     Num

        ; ...+ PE + 0f8h
        mov 	edx,lpFile
        add 	edx,[edx+03ch]
        add     eax, edx
        add     eax, 0f8h ; size of PE header
        ret
SectionHeadPtr endp

align 16

SectionCount proc iBase: DWORD

        mov 	eax,iBase
        add 	eax,[eax+03ch]
        movzx   eax, word ptr[eax+06h]
        ret
SectionCount endp

align 16

IsThisFilePEValid proc  uses edi lpFile:DWORD
	LOCAL hFile,pMem,fSize:DWORD
	LOCAL retv,lbrw:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__itfpv
	
	mov 	retv,0
	
	invoke 	CreateFile,lpFile,GENERIC_READ,
			FILE_SHARE_READ,0,OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		invoke 	GetFileSize,eax,0
		.if 	eax
			mov 	fSize,eax
			valloc 	eax
			.if 	eax
				mov 	pMem,eax
				
				lea 	edx,lbrw
				invoke 	ReadFile,hFile,eax,fSize,edx,0
				test 	eax,eax
				jz 		@err
				
				
				mov 	edi,pMem
				cmp 	word ptr [edi],'ZM'
				jne 	@err
				add 	edi,03ch
				add 	di,[edi]
				sub 	di,03ch
				cmp 	word ptr [edi],'EP'
				jne 	@err
				assume 	edi:ptr IMAGE_NT_HEADERS
				movzx 	eax,[edi].FileHeader.NumberOfSections
				test 	eax,eax
				jz 		@err
				mov 	eax,[edi].OptionalHeader.AddressOfEntryPoint
				test 	eax,eax
				jz 		@err
				assume 	edi:nothing
				
				mov 	retv,1
				@err:
				vfree 	pMem
			.endif
			
		.endif
		
		invoke 	CloseHandle,hFile
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__itfpv
		ErrorDump 	"IsThisFilePEValid",offset IsThisFilePEValid,"peoperations.asm"
	SehEnd		__itfpv
	
	mov 	eax,retv
	ret

IsThisFilePEValid endp

align 16

;-------------------------------------- MACRO-MACRO ----------------------------------------;
rawptr MACRO va, ibase, section
	
	sub 	va,ibase
	sub 	va,[section.IMAGE_SECTION_HEADER.VirtualAddress]
	add 	va,[section.IMAGE_SECTION_HEADER.PointerToRawData]
	
endm

nthead	MACRO ibase
	mov 	eax,ibase
	add 	ax,03ch
	add 	ax,[eax]
	sub 	ax,03ch
endm

sectbase MACRO req, nthdr
	mov 	req,sizeof IMAGE_NT_HEADERS
	sub 	req,sizeof IMAGE_OPTIONAL_HEADER32
	push 	eax
	movzx 	eax,[nthdr.IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
	add 	req,eax
	pop 	eax
	add 	req,nthdr
endm

