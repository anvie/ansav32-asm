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

;
;
;	UPX Section unpacker written by anvie based original UPX DynLoader
;	part engine ANSAV
;
;

;pemakaian :
;	IN		ESI = packed data (in section 2 UPX1)
;	IN OUT	EDI = mapped memory to store unpacked data

.code

;-------------------------------------- type 1 ----------------------------------------;

UPX_unpack_type1 proc

		pushad

		; ------- install seh ------- ;
		SehBegin	__upxunpack

		; Virtual Address Section 2 UPX1
		; Virtual Address Section 1 UPX0
		push	edi
		or		ebp, 0ffffffffh					; fill ebp 0xFFFFFFFFh
		jmp		@DoUnpack						;

		align 4

@loop1:

		mov		al, byte ptr [esi]			; ambil 1 byte ke al
		inc		esi							; inc source packed data pointer (section 2) UPX0 VA
		mov		byte ptr [edi], al			; tulis ke section 1 UPX1 VA
		inc		edi							; inc destination data	pointer (section 1) UPX1 VA

@A_004289CE:

		add		ebx, ebx
		jnz		@ccary ; @ccary

@DoUnpack:

		mov		ebx, dword ptr [esi]		; dapatkan 4 DWROD nilai dari section 2 UPX0 VA
		sub		esi, -4						; tambahkan esi dengan 4
		adc		ebx, ebx					; tambah dg carry flag

@ccary:

		jb		@loop1
		mov		eax, 1

@A_004289E0:

		add		ebx, ebx
		jnz		@ebxnozero
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@ebxnozero:

		adc		eax, eax
		add		ebx, ebx
		jnb		@A_004289E0
		jnz		@A_004289FC
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx
		jnb		@A_004289E0

@A_004289FC:

		xor		ecx, ecx
		sub		eax, 3
		jb		@A_00428A10
		shl		eax, 8
		mov		al, byte ptr [esi]
		inc		esi
		xor		eax, 0ffffffffh
		je		@Endl
		mov		ebp, eax

@A_00428A10:

		add		ebx, ebx
		jnz		@A_00428A1B
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@A_00428A1B:

		adc		ecx, ecx
		add		ebx, ebx
		jnz		@A_00428A28
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@A_00428A28:

		adc		ecx, ecx
		jnz		@A_00428A4C
		inc		ecx

@A_00428A2D:

		add		ebx, ebx
		jnz		@A_00428A38
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@A_00428A38:

		adc		ecx, ecx
		add		ebx, ebx
		jnb		@A_00428A2D
		jnz		@A_00428A49
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx
		jnb		@A_00428A2D

@A_00428A49:

		add		ecx, 2

@A_00428A4C:

		cmp		ebp, -0d00h
		adc		ecx, 1							; jumlah byte kembar
		lea		edx, dword ptr [edi+ebp]		; load alamat VA section 1 UPX0 ke EDX
		cmp		ebp, -4
		jbe		@A_00428A6C

@A_00428A5D:

		mov		al, byte ptr [edx]				; ambil 1 byte data sebelumnya dari sect 1 UPX0 VA
		inc		edx								; untuk dikloning ke offset selanjutnya
		mov		byte ptr [edi], al				; kloning
		inc		edi
		dec		ecx								; dec pointer
		jnz		@A_00428A5D
		jmp		@A_004289CE
		nop

@A_00428A6C:

		mov		eax, dword ptr [edx]
		add		edx, 4
		mov		dword ptr [edi], eax
		add		edi, 4
		sub		ecx, 4
		ja		@A_00428A6C
		add		edi, ecx
		jmp		@A_004289CE

@Endl:
		add		esp,4

		; ------- Seh trap ------- ;
		SehTrap		__upxunpack
			popad
			xor		eax,eax
			retn
		SehEnd		__upxunpack

		popad
		xor		eax,eax
		inc		eax
		retn
UPX_unpack_type1 endp

;-------------------------------------- type 2 ----------------------------------------;

align 16

UPX_unpack_type2 proc

		pushad

		; ------- seh installation ------- ;
		SehBegin	__upxunpack

		push	edi
		or		ebp, 0ffffffffh
		jmp		@a_0048ee92

		align 4

@a_0048ee88:

		mov		al, byte ptr [esi]
		inc		esi
		mov		byte ptr [edi], al
		inc		edi

@a_0048ee8e:

		add		ebx, ebx
		jnz		@a_0048ee99

@a_0048ee92:

		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048ee99:

		jb		@a_0048ee88
		mov		eax, 1

@a_0048eea0:

		add		ebx, ebx
		jnz		@a_0048eeab
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048eeab:

		adc		eax, eax
		add		ebx, ebx
		jnb		@a_0048eebc
		jnz		@a_0048eedb
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx
		jb		@a_0048eedb

@a_0048eebc:

		dec		eax
		add		ebx, ebx
		jnz		@a_0048eec8
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048eec8:

		adc		eax, eax
		jmp		@a_0048eea0

@a_0048eecc:

		add		ebx, ebx
		jnz		@a_0048eed7
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048eed7:

		adc		ecx, ecx
		jmp		@a_0048ef2d

@a_0048eedb:

		xor		ecx, ecx
		sub		eax, 3
		jb		@a_0048eef3
		shl		eax, 8
		mov		al, byte ptr [esi]
		inc		esi
		xor		eax, 0ffffffffh
		je		@a_0048ef62
		sar		eax, 1
		mov		ebp, eax
		jmp		@a_0048eefe

@a_0048eef3:

		add		ebx, ebx
		jnz		@a_0048eefe
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048eefe:

		jb		@a_0048eecc
		inc		ecx
		add		ebx, ebx
		jnz		@a_0048ef0c
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048ef0c:

		jb		@a_0048eecc

@a_0048ef0e:

		add		ebx, ebx
		jnz		@a_0048ef19
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx

@a_0048ef19:

		adc		ecx, ecx
		add		ebx, ebx
		jnb		@a_0048ef0e
		jnz		@a_0048ef2a
		mov		ebx, dword ptr [esi]
		sub		esi, -4
		adc		ebx, ebx
		jnb		@a_0048ef0e

@a_0048ef2a:

		add		ecx, 2

@a_0048ef2d:

		cmp		ebp, -0500h
		adc		ecx, 2
		lea		edx, dword ptr [edi+ebp]
		cmp		ebp, -4
		jbe		@a_0048ef4c

@a_0048ef3e:

		mov		al, byte ptr [edx]
		inc		edx
		mov		byte ptr [edi], al
		inc		edi
		dec		ecx
		jnz		@a_0048ef3e
		jmp		@a_0048ee8e

@a_0048ef4c:

		mov		eax, dword ptr [edx]
		add		edx, 4
		mov		dword ptr [edi], eax
		add		edi, 4
		sub		ecx, 4
		ja		@a_0048ef4c
		add		edi, ecx
		jmp		@a_0048ee8e

@a_0048ef62:

		add		esp,4

		SehTrap		__upxunpack
			popad
			xor		eax,eax
			retn
		SehEnd		__upxunpack

		popad
		xor		eax,eax
		inc		eax
	ret

UPX_unpack_type2 endp

; ------- main ------- ;
align 16

upx_unpack_all proc	uses edi ibase:DWORD,isize:DWORD

	LOCAL 	ntheader,scbase:DWORD
	LOCAL 	sectnum:DWORD
	LOCAL 	dstmem,dstmemsize:DWORD
	LOCAL 	retv:DWORD

	SehBegin 	__upxunpackall

	sub 	eax,eax
	mov 	retv,eax

	mov 	eax,ibase
	add 	ax,03ch
	add 	ax,[eax]
	sub 	ax,03ch
	mov 	ntheader,eax

	movzx 	ecx,[eax.IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
	mov 	sectnum,ecx

	push 	ecx

	mov 	ecx,eax
	add 	ecx,sizeof IMAGE_NT_HEADERS
	sub 	ecx,sizeof IMAGE_OPTIONAL_HEADER32

	movzx 	eax,[eax.IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
	add 	ecx,eax
	mov 	scbase,ecx

	assume 	ecx:ptr IMAGE_SECTION_HEADER

	pop 	eax

	mov 	edx,[ecx].Misc.VirtualSize

	mov 	eax,ntheader
	add 	edx,[eax.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage]

	.if 	edx>2000000
		SehPop
		xor 	eax,eax
		ret
	.endif

	test 	edx,edx
	jz 		@nodstmem

	mov 	dstmemsize,edx

	valloc 	edx
	.if 	eax
		mov 	dstmem,eax
		push 	eax

		; ------- get packed data ------- ;
		mov 	edi,ibase
		mov 	ecx,scbase
		add 	ecx,sizeof IMAGE_SECTION_HEADER
		mov 	eax,[ecx].PointerToRawData
		lea 	esi,[edi+eax]

		pop 	edi

		call 	UPX_unpack_type1
		.if 	!eax
			call 	UPX_unpack_type2
			.if 	!eax
				vfree 	edi
				jmp 	@endl
			.endif
		.endif

		.if 	eax
			mov2 	retv,dstmem
			mov 	ecx,dstmemsize
		.endif
	.endif


	assume 	ecx:nothing

@nodstmem:
@endl:

	SehTrap 	__upxunpackall
	SehEnd 		__upxunpackall

	mov 	eax,retv
	ret

upx_unpack_all endp



