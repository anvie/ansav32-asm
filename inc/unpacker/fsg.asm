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
;	FSG v2.0 section unpacker written by anvie based on FSG DynLoader
;	the part unpacker engine of ANSAV
;
;

;-------------------------------------- code ----------------------------------------;

.data
	fsgsz	dd 0
	fsgdata dd offset ebx_stuff,ebx_4,ebx_8
.code

;
;	pemakaian :
;				IN ESI = Packed data offset
;				OUT EDI = unpacked (stored data)
;
;  	retv = 1 if success and 0 if fuckin error raised
;

FSG_unpack proc uses esi edi ebx
	
		push    ebp
		
		; ------- Seh Begin ------- ;
		SehBegin 	__fsgunpack

		lea 	ebx,fsgdata
		xor 	edx,edx
		mov 	dl, 080h
@fsg_0040015d:
		
        movs    byte ptr es:[edi], byte ptr [esi]
        mov     dh, 080h

@fsg_00400160:

        call    dword ptr [ebx]
        jnb     @fsg_0040015d
        xor     ecx, ecx
        call    dword ptr [ebx]
        jnb     @fsg_00400180
        xor     eax, eax
        call    dword ptr [ebx]
        jnb     @fsg_0040018f
        mov     dh, 080h
        inc     ecx
        mov     al, 010h

@fsg_00400175:

        call    dword ptr [ebx]
        adc     al, al
        jnb     @fsg_00400175
        jnz     @fsg_004001b7
        stos    byte ptr es:[edi]
        jmp     @fsg_00400160

@fsg_00400180:

        call    dword ptr [ebx+8]
        add     dh, dh
        sbb     ecx, 1
        jnz     @fsg_00400198
        call    dword ptr [ebx+4]
        jmp     @fsg_004001b3

@fsg_0040018f:

        lods    byte ptr [esi]
        shr     eax, 1
        je      @fsg_004001c1
        adc     ecx, ecx
        jmp     @fsg_004001b0

@fsg_00400198:

        xchg    eax, ecx
        dec     eax
        shl     eax, 8
        lods    byte ptr [esi]
        call    dword ptr [ebx+4]
        ;cmp     eax, dword ptr [ebx-8]
        cmp 	eax, fsgsz
        
        jnb     @fsg_004001b0
        cmp     ah, 5
        jnb     @fsg_004001b1
        cmp     eax, 07fh
        ja      @fsg_004001b2

@fsg_004001b0:

        inc     ecx

@fsg_004001b1:

        inc     ecx

@fsg_004001b2:

        xchg    eax, ebp

@fsg_004001b3:

        mov     eax, ebp
        mov     dh, 0

@fsg_004001b7:

        push    esi
        mov     esi, edi
        sub     esi, eax
        rep     movs byte ptr es:[edi], byte ptr [esi]
        pop     esi
        jmp     @fsg_00400160

@fsg_004001c1:

		; ------- uneeded ------- ;
		; part berikut tidak diperlukan
		; karena hanya merupakan bagian untuk membangun IAT aja
;        pop     esi
;
;@fsg_004001c2:
;
;        lods    dword ptr [esi]
;        xchg    eax, edi
;        lods    dword ptr [esi]
;        push    eax
;        call    dword ptr [ebx+010h]	; LoadLibraryA
;        xchg    eax, ebp
;
;@fsg_004001ca:
;
;        mov     eax, dword ptr [edi]
;        inc     eax
;        js      @fsg_004001c2
;        jnz     @fsg_004001d4
;        jmp     dword ptr [ebx+0ch] ; jump to host!
		
		;add 	esp,4
		;retn

;@fsg_004001d4:
;
;        push    eax
;        push    ebp
;        call    dword ptr [ebx+014h]
;        stos    dword ptr es:[edi]
		; -------------- ;
		
		
        jmp     @endl
ebx_4 equ $
        xor     ecx, ecx
ebx_8 equ $
        inc     ecx

@fsg_004001df:

        call    dword ptr [ebx]
        adc     ecx, ecx
        call    dword ptr [ebx]
        jb      @fsg_004001df
        retn
@endl:
		SehTrap 	__fsgunpack
			pop 	ebp
			xor 	eax,eax
			ret
		SehEnd 		__fsgunpack
		pop 	ebp
		xor 	eax,eax
		inc 	eax
		ret

FSG_unpack endp

align 16
ebx_stuff proc
        add     dl, dl
        jnz     @fsg_004001f1
        mov     dl, byte ptr [esi]
        inc     esi
        adc     dl, dl

@fsg_004001f1:

        retn
ebx_stuff endp

align 16
fsg_unpack_all  proc uses esi edi ibase:DWORD, isize:DWORD
	
	LOCAL 	unpacked_data:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__fsgunpack
	
	mov 	unpacked_data,0
	
	mov 	edi,ibase
	nthead	edi
	
	push 	eax
	
	mov 	edx,[eax.IMAGE_NT_HEADERS.OptionalHeader.ImageBase]

	sectbase	ecx,eax
	
	push 	ecx
	
	; ------- find EP ------- ;
	mov 	eax,ecx
	
	mov 	ecx,isize
	lea 	ecx,[eax+ecx-032h] ; secure
	
	.while 	TRUE
		cmp 	dword ptr [eax],0A4559461H
		.if 	zero?
			.break
		.endif
		add 	eax,1
		.if 	eax>=ecx
			add 	esp,4
			xor 	eax,eax
			SehPop
			ret
		.endif
	.endw
	
	pop 	ecx
	
	; ------- get fsg data header ------- ;
	lea 	eax,[eax-04h]
	mov 	eax,[eax]
	lea 	ecx,[ecx+sizeof IMAGE_SECTION_HEADER]
	rawptr	eax, edx, ecx
	lea 	eax,[eax+edi]
	mov 	eax,[eax]
	rawptr 	eax, edx, ecx
	lea 	eax,[eax+edi]
	m2m 	fsgsz,[eax+4*6]
	
	; ------- get source fsg packed data ------- ;
	mov 	esi,[eax+04h]
	rawptr 	esi, edx, ecx
	lea 	esi,[esi+edi]
	
	pop 	eax
	
	; ------- get dstmem size + safe page ------- ;
	mov 	ecx,[ecx.IMAGE_SECTION_HEADER.Misc.VirtualSize]
	add 	ecx,[eax.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage]
	
	cmp 	ecx,20000000
	ja 		@badsize
	
	push 	ecx
	
	valloc 	ecx
	.if 	eax
		mov 	unpacked_data,eax
		mov 	edi,eax
		call 	FSG_unpack
		.if 	eax
			mov 	eax,edi
			pop		ecx
			SehPop
			ret
		.endif
	.endif
	
	add 	esp,4h
@badsize:
	
	SehTrap 	__fsgunpack
	SehEnd 		__fsgunpack
	
	.if 	unpacked_data
		vfree 	unpacked_data
	.endif
	
	xor 	eax,eax
	ret

fsg_unpack_all endp

