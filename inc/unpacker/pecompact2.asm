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
;	PECompact v2.x section unpacker engine written by anvie based pec2 DynLoader
;	the part engine of ANSAV 
;
;
;
;-------------------------------------- code ----------------------------------------;

.code

; pemakaian :
; 			IN ESI 	= packed data
;			OUT EDI = mem to store unpacked data
;
align 16
; uses aPlib compression algorithm
PEC2_unpack_aplib proc

        pushad
        
        SehBegin 	__pec2unp
        
        cld
        lods    dword ptr [esi]
        xor     ecx, ecx
        test    eax, eax
        je      @pec2_00401022
        xor     edx, edx
        lea     ebx, dword ptr [eax+edi]

@pec2_00401016:

        movs    byte ptr es:[edi], byte ptr [esi]
        mov     cl, 3

@pec2_00401019:

        call    @pec2_00401090
        jnb     @pec2_00401016
        cmp     edi, ebx

@pec2_00401022:

        jnb     @pec2_004010ad
        push    ebx
        push    ebp
        push    edi
        xor     ebx, ebx
        inc     ebx
        xor     ebp, ebp
        mov     eax, ebx

@pec2_00401032:

        lea     edi, dword ptr [ebp+ebx]
        mov     ebp, ebx
        mov     ebx, edi
        call    @pec2_00401090
        jnb     @pec2_00401032
        lea     ebx, dword ptr [ebp+edi]
        add     eax, edi
        mov     ebp, edi
        call    @pec2_00401090
        jnb     @pec2_00401032
        pop     edi
        pop     ebp
        pop     ebx
        sub     eax, ecx
        jnb     @pec2_00401060
        mov     eax, ebp
        call    @pec2_0040109b
        jmp     @pec2_00401084

@pec2_00401060:

        mov     cl, 6

@pec2_00401062:

        call    @pec2_00401090
        adc     eax, eax
        dec     ecx
        jnz     @pec2_00401062
        inc     eax
        call    @pec2_0040109b
        mov     ebp, eax
        cmp     eax, 08001h
        sbb     ecx, -1
        cmp     eax, 0781h
        sbb     ecx, -1

@pec2_00401084:

        push    esi
        mov     esi, edi
        sub     esi, eax
        rep     movs byte ptr es:[edi], byte ptr [esi]
        pop     esi
        inc     ecx
        inc     ecx
        jmp     @pec2_00401019
        
@pec2_00401090:

        add     edx, edx
        jnz     @pec2_0040109a
        xchg    eax, edx
        lods    dword ptr [esi]
        xchg    eax, edx
        add     edx, edx
        inc     edx

@pec2_0040109a:

        retn
        
@pec2_004010ad:
        sub     edi, dword ptr [esp+028h]
        mov     dword ptr [esp+01ch], edi
        
        SehTrap 	__pec2unp
        	popad
        	xor 	eax,eax
        	retn
        SehEnd		__pec2unp
        
        popad
        xor 	eax,eax
        inc 	eax
		retn
        
@pec2_0040109b:

        xor     ecx, ecx
        inc     ecx

@pec2_0040109e:

        call    @pec2_00401090
        adc     ecx, ecx
        call    @pec2_00401090
        jb      @pec2_0040109e
        retn
        
PEC2_unpack_aplib endp

;
; LZMA Special
; written by anvie based on PEc2 DynLoader
;  
;
; prototipe :
;			PEC2_unpack_lzma proto source:DWORD, destination:DWORD, WorkMem:DWORD, lzmaStub:DWORD
;
;

.data?
	pec2lzma1 dd ?
	ebp_p8 dd ?
	ebp_pb db ?
.code

align 16

PEC2_unpack_lzma proc

        push    ebp
        mov     ebp, esp
        sub     esp, 034h
        
        ; ------- seh installtion ------- ;
        SehBegin 	__pec2unp
        
        
        mov     eax, dword ptr [ebp+(010h+04h)]
        mov     ecx, dword ptr [eax+8]
        
        and     dword ptr [ebp-010h], 0
        and     dword ptr [ebp-8], 0
        xor     edx, edx
        inc     edx
        push    ebx
        push    esi
        
        mov 	esi,[ebp+(0Ch+04h)]				; get WorkMem
        
        push    edi
        mov     ebx, edx
        shl     ebx, cl
        mov     ecx, dword ptr [eax+04h]
        mov     eax, dword ptr [eax]
        mov     edi, edx
        shl     edi, cl
        mov     dword ptr [ebp-02ch], eax
        add     ecx, eax
        mov     eax, 0300h
        shl     eax, cl
        dec     ebx
        dec     edi
        mov     dword ptr [ebp-014h], esi
        add     eax, 0736h

        mov     ebp_pb, 0
        mov     dword ptr [ebp-030h], ebx
        mov     dword ptr [ebp-034h], edi
        mov     dword ptr [ebp-018h], edx
        mov     dword ptr [ebp-020h], edx
        mov     dword ptr [ebp-01ch], edx
        mov     dword ptr [ebp-024h], edx
        je      @pec2lzma_0040108c
        mov     ecx, eax
        mov     eax, 0400h
        mov     edi, esi
        rep     stos dword ptr es:[edi]

@pec2lzma_0040108c:

        mov 	eax,[ebp+(04h+04h)]
        and     dword ptr [ebp+(04h+04h)], 0
        push    5
        mov     dword ptr [ebp-4], eax
        or      eax, 0ffffffffh
        pop     ecx

@pec2lzma_0040109c:

        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        inc     dword ptr [ebp-4]
        dec     ecx
        mov     dword ptr [ebp+(04h+04h)], edx
        jnz     @pec2lzma_0040109c

        cmp 	pec2lzma1,ecx
        ja      @pec2lzma_004010c4

;@pec2lzma_004010b8:



@pec2lzma_004010ba:

        pop     edi
        pop     esi
        pop     ebx
        
        ; ------- seh trap  ------- ;
        SehTrap 	__pec2unp
	        pop     edi
	        pop     esi
	        pop     ebx
        	xor 	eax,eax
        	leave 
        	retn 	010h
        SehEnd 		__pec2unp

		xor 	eax,eax
		inc 	eax
        leave
        retn 	010h

@pec2lzma_004010c1:

        mov     ebx, dword ptr [ebp-030h]

@pec2lzma_004010c4:

        and     ebx, dword ptr [ebp-010h]
        mov     ecx, dword ptr [ebp-8]
        mov     edx, dword ptr [ebp-014h]
        shl     ecx, 4
        add     ecx, ebx
        cmp     eax, 01000000h
        lea     edi, dword ptr [edx+ecx*4]
        jnb     @pec2lzma_004010f3
        mov     edx, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   edx, byte ptr [edx]
        shl     ecx, 8
        or      ecx, edx
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_004010f3:

        mov     ecx, dword ptr [edi]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401285
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     dword ptr [edi], esi

        movzx   esi, ebp_pb
        mov     edi, dword ptr [ebp-034h]
        and     edi, dword ptr [ebp-010h]
        push    8
        pop     ecx
        sub     cl, byte ptr [ebp-02ch]
        xor     edx, edx
        shr     esi, cl
        mov     ecx, dword ptr [ebp-02ch]
        shl     edi, cl
        mov     ecx, dword ptr [ebp-014h]
        inc     edx
        add     esi, edi
        imul    esi, esi, 0c00h
        cmp     dword ptr [ebp-8], 7
        lea     ecx, dword ptr [esi+ecx+01cd8h]

        mov     ebp_p8, ecx
        jl      @pec2lzma_004011ee
        mov     ecx, dword ptr [ebp-010h]
        sub     ecx, dword ptr [ebp-018h]
        mov 	esi,dword ptr [ebp+(08h+04h)]
        
        movzx   ecx, byte ptr [ecx+esi]
        mov     dword ptr [ebp-0ch], ecx

@pec2lzma_0040115f:

        shl     dword ptr [ebp-0ch], 1
        mov     edi, dword ptr [ebp-0ch]
        mov     esi, ebp_p8
        and     edi, 0100h
        cmp     eax, 01000000h
        lea     ecx, dword ptr [edi+edx]
        lea     ecx, dword ptr [esi+ecx*4+0400h]
        mov     dword ptr [ebp-028h], ecx
        jnb     @pec2lzma_00401199
        mov     ebx, dword ptr [ebp-4]
        mov     esi, dword ptr [ebp+(04h+04h)]
        movzx   ebx, byte ptr [ebx]
        shl     esi, 8
        or      esi, ebx
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], esi

@pec2lzma_00401199:

        mov     ecx, dword ptr [ecx]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_004011c7
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     ecx, dword ptr [ebp-028h]
        add     edx, edx
        test    edi, edi
        mov     dword ptr [ecx], esi
        jnz     @pec2lzma_00401247
        jmp     @pec2lzma_004011e0

@pec2lzma_004011c7:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        test    edi, edi
        mov     esi, dword ptr [ebp-028h]
        mov     dword ptr [esi], ecx
        lea     edx, dword ptr [edx+edx+1]
        je      @pec2lzma_00401247

@pec2lzma_004011e0:

        cmp     edx, 0100h
        jl      @pec2lzma_0040115f
        jmp     @pec2lzma_0040124f

@pec2lzma_004011ee:

        cmp     eax, 01000000h
        mov     ecx, ebp_p8
        lea     edi, dword ptr [ecx+edx*4]
        jnb     @pec2lzma_00401212
        mov     esi, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     ecx, 8
        or      ecx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_00401212:

        mov     ecx, dword ptr [edi]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401235
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     dword ptr [edi], esi
        add     edx, edx
        jmp     @pec2lzma_00401247

@pec2lzma_00401235:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        mov     dword ptr [edi], ecx
        lea     edx, dword ptr [edx+edx+1]

@pec2lzma_00401247:

        cmp     edx, 0100h
        jl      @pec2lzma_004011ee

@pec2lzma_0040124f:

        mov     esi, dword ptr [ebp-010h]
        mov     ecx, dword ptr [ebp+(08h+04h)]
        inc     dword ptr [ebp-010h]
        cmp     dword ptr [ebp-8], 4
        mov     ebp_pb, dl
        mov     byte ptr [esi+ecx], dl
        jge     @pec2lzma_0040126d
        and     dword ptr [ebp-8], 0
        jmp     @pec2lzma_00401807

@pec2lzma_0040126d:

        cmp     dword ptr [ebp-8], 0ah
        jge     @pec2lzma_0040127c
        sub     dword ptr [ebp-8], 3
        jmp     @pec2lzma_00401807

@pec2lzma_0040127c:

        sub     dword ptr [ebp-8], 6
        jmp     @pec2lzma_00401807

@pec2lzma_00401285:

        sub     dword ptr [ebp+(04h+04h)], esi
        mov     edx, ecx
        shr     edx, 5
        sub     ecx, edx
        mov     edx, dword ptr [ebp-014h]
        sub     eax, esi
        cmp     eax, 01000000h
        mov     dword ptr [edi], ecx
        mov     ecx, dword ptr [ebp-8]
        lea     edx, dword ptr [edx+ecx*4+0300h]
        jnb     @pec2lzma_004012be
        mov     esi, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     ecx, 8
        or      ecx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_004012be:

        mov     ecx, dword ptr [edx]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401310
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        cmp     dword ptr [ebp-8], 7
        mov     ecx, dword ptr [ebp-01ch]
        mov     dword ptr [ebp-024h], ecx
        mov     ecx, dword ptr [ebp-020h]
        mov     dword ptr [ebp-01ch], ecx
        mov     ecx, dword ptr [ebp-018h]
        mov     dword ptr [edx], esi
        mov     dword ptr [ebp-020h], ecx
        jge     @pec2lzma_004012fb
        and     dword ptr [ebp-8], 0
        jmp     @pec2lzma_00401302

@pec2lzma_004012fb:

        mov     dword ptr [ebp-8], 3

@pec2lzma_00401302:

        mov     ecx, dword ptr [ebp-014h]
        add     ecx, 0cc8h
        jmp     @pec2lzma_00401503

@pec2lzma_00401310:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        cmp     eax, 01000000h
        mov     dword ptr [edx], ecx
        mov     ecx, dword ptr [ebp-8]
        mov     edx, dword ptr [ebp-014h]
        lea     edi, dword ptr [edx+ecx*4+0330h]
        jnb     @pec2lzma_00401349
        mov     edx, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   edx, byte ptr [edx]
        shl     ecx, 8
        or      ecx, edx
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_00401349:

        mov     ecx, dword ptr [edi]
        mov     edx, eax
        shr     edx, 0bh
        imul    edx, ecx
        cmp     dword ptr [ebp+(04h+04h)], edx
        jnb     @pec2lzma_00401407
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     ecx, dword ptr [ebp-8]
        add     ecx, 0fh
        shl     ecx, 4
        mov     dword ptr [edi], esi
        mov     esi, dword ptr [ebp-014h]
        add     ecx, ebx
        cmp     edx, 01000000h
        mov     eax, edx
        lea     esi, dword ptr [esi+ecx*4]
        jnb     @pec2lzma_0040139e
        mov     ecx, dword ptr [ebp+(04h+04h)]
        shl     edx, 8
        mov     eax, edx
        mov     edx, dword ptr [ebp-4]
        movzx   edx, byte ptr [edx]
        shl     ecx, 8
        or      ecx, edx
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_0040139e:

        mov     ecx, dword ptr [esi]
        mov     edx, eax
        shr     edx, 0bh
        imul    edx, ecx
        cmp     dword ptr [ebp+(04h+04h)], edx
        jnb     @pec2lzma_004013f4
        mov     eax, edx
        mov     edx, 0800h
        sub     edx, ecx
        shr     edx, 5
        add     edx, ecx
        cmp     dword ptr [ebp-010h], 0
        mov     dword ptr [esi], edx
        je      @pec2lzma_00401818
        mov     edx, dword ptr [ebp+(08h+04h)]
        mov     esi, dword ptr [ebp-010h]
        xor     ecx, ecx
        cmp     dword ptr [ebp-8], 7
        setge   cl
        lea     ecx, dword ptr [ecx+ecx+9]
        mov     dword ptr [ebp-8], ecx
        mov     ecx, dword ptr [ebp-010h]
        sub     ecx, dword ptr [ebp-018h]
        inc     dword ptr [ebp-010h]
        mov     cl, byte ptr [ecx+edx]
        mov 	ebp_pb,cl
        mov     byte ptr [esi+edx], cl
        jmp     @pec2lzma_00401807

@pec2lzma_004013f4:

        sub     dword ptr [ebp+(04h+04h)], edx
        sub     eax, edx
        mov     edx, ecx
        shr     edx, 5
        sub     ecx, edx
        mov     dword ptr [esi], ecx
        jmp     @pec2lzma_004014e7

@pec2lzma_00401407:

        sub     dword ptr [ebp+(04h+04h)], edx
        sub     eax, edx
        mov     edx, ecx
        shr     edx, 5
        sub     ecx, edx
        cmp     eax, 01000000h
        mov     edx, dword ptr [ebp-014h]
        mov     dword ptr [edi], ecx
        mov     ecx, dword ptr [ebp-8]
        lea     edx, dword ptr [edx+ecx*4+0360h]
        jnb     @pec2lzma_00401440
        mov     esi, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     ecx, 8
        or      ecx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_00401440:

        mov     ecx, dword ptr [edx]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401464
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     ecx, dword ptr [ebp-020h]
        mov     dword ptr [edx], esi
        jmp     @pec2lzma_004014de

@pec2lzma_00401464:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        cmp     eax, 01000000h
        mov     dword ptr [edx], ecx
        mov     ecx, dword ptr [ebp-8]
        mov     edx, dword ptr [ebp-014h]
        lea     edx, dword ptr [edx+ecx*4+0390h]
        jnb     @pec2lzma_0040149d
        mov     esi, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     ecx, 8
        or      ecx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_0040149d:

        mov     ecx, dword ptr [edx]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_004014c1
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     ecx, dword ptr [ebp-01ch]
        mov     dword ptr [edx], esi
        jmp     @pec2lzma_004014d8

@pec2lzma_004014c1:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        mov     dword ptr [edx], ecx
        mov     edx, dword ptr [ebp-01ch]
        mov     ecx, dword ptr [ebp-024h]
        mov     dword ptr [ebp-024h], edx

@pec2lzma_004014d8:

        mov     edx, dword ptr [ebp-020h]
        mov     dword ptr [ebp-01ch], edx

@pec2lzma_004014de:

        mov     edx, dword ptr [ebp-018h]
        mov     dword ptr [ebp-020h], edx
        mov     dword ptr [ebp-018h], ecx

@pec2lzma_004014e7:

        xor     ecx, ecx
        cmp     dword ptr [ebp-8], 7
        setge   cl
        dec     ecx
        and     ecx, 0fffffffdh
        add     ecx, 0bh
        mov     dword ptr [ebp-8], ecx
        mov     ecx, dword ptr [ebp-014h]
        add     ecx, 014d0h

@pec2lzma_00401503:

        cmp     eax, 01000000h
        jnb     @pec2lzma_00401521
        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], edx

@pec2lzma_00401521:

        mov     edx, dword ptr [ecx]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, edx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401555
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, edx
        shr     esi, 5
        add     esi, edx
        shl     ebx, 5
        mov     dword ptr [ecx], esi
        lea     ecx, dword ptr [ebx+ecx+8]
        xor     edi, edi
        mov     ebp_p8, 3
        jmp     @pec2lzma_004015d6

@pec2lzma_00401555:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, edx
        shr     esi, 5
        sub     edx, esi
        cmp     eax, 01000000h
        mov     dword ptr [ecx], edx
        jnb     @pec2lzma_00401581
        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], edx

@pec2lzma_00401581:

        mov     edx, dword ptr [ecx+4]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, edx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_004015b7
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, edx
        shr     esi, 5
        add     esi, edx
        shl     ebx, 5
        mov     dword ptr [ecx+4], esi
        lea     ecx, dword ptr [ebx+ecx+0208h]
        push    8
        mov     ebp_p8, 3
        jmp     @pec2lzma_004015d5

@pec2lzma_004015b7:

        sub     dword ptr [ebp+(04h+04h)], esi
        sub     eax, esi
        mov     esi, edx
        shr     esi, 5
        sub     edx, esi
        mov     dword ptr [ecx+4], edx
        add     ecx, 0408h
        push    010h
        mov     ebp_p8, 8

@pec2lzma_004015d5:

        pop     edi

@pec2lzma_004015d6:

        mov     edx, ebp_p8
        mov     ebx, dword ptr [ebp-018h]
        mov     dword ptr [ebp-028h], edx
        mov     dword ptr [ebp-0ch], 1

@pec2lzma_004015e6:

        cmp     eax, 01000000h
        jnb     @pec2lzma_00401604
        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], edx

@pec2lzma_00401604:

        mov     edx, dword ptr [ebp-0ch]
        mov     edx, dword ptr [ecx+edx*4]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, edx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_00401630
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, edx
        shr     esi, 5
        add     esi, edx
        mov     edx, dword ptr [ebp-0ch]
        shl     dword ptr [ebp-0ch], 1
        mov     dword ptr [ecx+edx*4], esi
        jmp     @pec2lzma_0040164c

@pec2lzma_00401630:

        sub     dword ptr [ebp+(04h+04h)], esi
        mov     ebx, dword ptr [ebp-018h]
        sub     eax, esi
        mov     esi, edx
        shr     esi, 5
        sub     edx, esi
        mov     esi, dword ptr [ebp-0ch]
        mov     dword ptr [ecx+esi*4], edx
        lea     edx, dword ptr [esi+esi+1]
        mov     dword ptr [ebp-0ch], edx

@pec2lzma_0040164c:

        dec     dword ptr [ebp-028h]
        jnz     @pec2lzma_004015e6
        mov     ecx, ebp_p8
        xor     edx, edx
        inc     edx
        mov     esi, edx
        shl     esi, cl
        sub     edi, esi
        add     dword ptr [ebp-0ch], edi
        cmp     dword ptr [ebp-8], 4
        jge     @pec2lzma_004017d8
        add     dword ptr [ebp-8], 7
        cmp     dword ptr [ebp-0ch], 4
        jge     @pec2lzma_00401679
        mov     ecx, dword ptr [ebp-0ch]
        jmp     @pec2lzma_0040167c

@pec2lzma_00401679:

        push    3
        pop     ecx

@pec2lzma_0040167c:

        mov     edi, dword ptr [ebp-014h]
        shl     ecx, 8
        lea     ebx, dword ptr [ecx+edi+06c0h]
        mov     ebp_p8, 6

@pec2lzma_00401690:

        cmp     eax, 01000000h
        jnb     @pec2lzma_004016ae
        mov     esi, dword ptr [ebp-4]
        mov     ecx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     ecx, 8
        or      ecx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], ecx

@pec2lzma_004016ae:

        mov     ecx, dword ptr [ebx+edx*4]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, ecx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_004016d3
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, ecx
        shr     esi, 5
        add     esi, ecx
        mov     dword ptr [ebx+edx*4], esi
        add     edx, edx
        jmp     @pec2lzma_004016e9

@pec2lzma_004016d3:

        sub     dword ptr [ebp+(04h+04h)], esi
        mov     edi, dword ptr [ebp-014h]
        sub     eax, esi
        mov     esi, ecx
        shr     esi, 5
        sub     ecx, esi
        mov     dword ptr [ebx+edx*4], ecx
        lea     edx, dword ptr [edx+edx+1]

@pec2lzma_004016e9:

        dec     ebp_p8
        jnz     @pec2lzma_00401690
        sub     edx, 040h
        cmp     edx, 4
        mov     ebx, edx
        jl      @pec2lzma_004017ce
        mov     ecx, edx
        sar     ecx, 1
        and     ebx, 1
        dec     ecx
        or      ebx, 2
        cmp     edx, 0eh
        mov     dword ptr [ebp-028h], ecx
        jge     @pec2lzma_0040171e
        shl     ebx, cl
        mov     ecx, ebx
        sub     ecx, edx
        lea     ecx, dword ptr [edi+ecx*4+0abch]
        jmp     @pec2lzma_00401761

@pec2lzma_0040171e:

        sub     ecx, 4

@pec2lzma_00401721:

        cmp     eax, 01000000h
        jnb     @pec2lzma_0040173f
        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], edx

@pec2lzma_0040173f:

        shr     eax, 1
        add     ebx, ebx
        cmp     dword ptr [ebp+(04h+04h)], eax
        jb      @pec2lzma_0040174e
        sub     dword ptr [ebp+(04h+04h)], eax
        or      ebx, 1

@pec2lzma_0040174e:

        dec     ecx
        jnz     @pec2lzma_00401721
        lea     ecx, dword ptr [edi+0c88h]
        shl     ebx, 4
        mov     dword ptr [ebp-028h], 4

@pec2lzma_00401761:

        xor     edi, edi
        inc     edi
        mov     ebp_p8, ecx
        mov     dword ptr [ebp-018h], edi

@pec2lzma_0040176a:

        cmp     eax, 01000000h
        jnb     @pec2lzma_00401788
        mov     esi, dword ptr [ebp-4]
        mov     edx, dword ptr [ebp+(04h+04h)]
        movzx   esi, byte ptr [esi]
        shl     edx, 8
        or      edx, esi
        shl     eax, 8
        inc     dword ptr [ebp-4]
        mov     dword ptr [ebp+(04h+04h)], edx

@pec2lzma_00401788:

        mov     edx, dword ptr [ecx+edi*4]
        mov     esi, eax
        shr     esi, 0bh
        imul    esi, edx
        cmp     dword ptr [ebp+(04h+04h)], esi
        jnb     @pec2lzma_004017ad
        mov     eax, esi
        mov     esi, 0800h
        sub     esi, edx
        shr     esi, 5
        add     esi, edx
        mov     dword ptr [ecx+edi*4], esi
        add     edi, edi
        jmp     @pec2lzma_004017c6

@pec2lzma_004017ad:

        sub     dword ptr [ebp+(04h+04h)], esi
        mov     ecx, edx
        shr     ecx, 5
        sub     edx, ecx
        mov     ecx, ebp_p8
        sub     eax, esi
        or      ebx, dword ptr [ebp-018h]
        mov     dword ptr [ecx+edi*4], edx
        lea     edi, dword ptr [edi+edi+1]

@pec2lzma_004017c6:

        shl     dword ptr [ebp-018h], 1
        dec     dword ptr [ebp-028h]
        jnz     @pec2lzma_0040176a

@pec2lzma_004017ce:

        inc     ebx
        mov     dword ptr [ebp-018h], ebx
        je      @pec2lzma_004010ba

@pec2lzma_004017d8:

        mov     esi, dword ptr [ebp-010h]
        add     dword ptr [ebp-0ch], 2
        cmp     ebx, esi
        ja      @pec2lzma_00401818
        mov     edi, dword ptr [ebp+(08h+04h)]
        mov     ecx, esi
        sub     ecx, ebx
        add     ecx, edi

@pec2lzma_004017ec:

        mov     dl, byte ptr [ecx]
        dec     dword ptr [ebp-0ch]
        mov     byte ptr [esi+edi], dl
        inc     esi
        inc     ecx
        cmp     dword ptr [ebp-0ch], 0
        mov 	ebp_pb,dl
        mov     dword ptr [ebp-010h], esi
        je      @pec2lzma_00401807
        cmp     esi, pec2lzma1
        jb      @pec2lzma_004017ec

@pec2lzma_00401807:

        mov     ecx, pec2lzma1
        cmp     dword ptr [ebp-010h], ecx
        jb      @pec2lzma_004010c1
        jmp     @pec2lzma_004010ba

@pec2lzma_00401818:

        xor     eax, eax
        inc     eax
        jmp     @pec2lzma_004010ba
PEC2_unpack_lzma endp

align 16

pecompact_unpack_all proc uses esi edi ibase:DWORD, isize:DWORD

	LOCAL 	sectionbase,ntheader,epptr,pec2_method:DWORD
	LOCAL	srcmem,dstmem,dstmemsize,workmem,retv:DWORD 	
	LOCAL 	pec2_bs[2]:DWORD
	
	SehBegin 	__pec2unp
	
	sub 	eax,eax
	mov 	retv,eax
	mov 	dstmem,eax
	mov 	workmem,eax
	mov 	dstmemsize,eax
	
	; make new duplicated image, we will use it for accept read write access
	; to paged memory we made
	mov 	esi,isize
	valloc 	esi
	test 	eax,eax
	jnz		@F
		SehPop
		ret
	@@:
	mov 	srcmem,eax
	
	invoke 	MyCopyMem,eax,ibase,esi
	
	nthead	srcmem
	mov 	ntheader,eax
	sectbase	ecx,eax
	mov 	sectionbase,ecx
	
	; ------- get compression method aplib/lzma ------- ;
	; get EP
	mov 	edi,srcmem
	push 	[eax.IMAGE_NT_HEADERS.OptionalHeader.ImageBase]
	mov 	eax,[eax.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint]
	rawptr	eax,0,ecx
	lea 	eax,[edi+eax]	; EP
	mov 	epptr,eax
	
	inc 	eax
	mov 	eax,[eax]
	pop 	edx
	add 	ecx,sizeof IMAGE_SECTION_HEADER
	rawptr	eax,edx,ecx
	lea 	eax,[eax+edi]
	inc 	eax
	mov 	eax,[eax]
	lea 	esi,[eax+010001257h]
	rawptr	esi,edx,ecx
	lea 	esi,[esi+edi]
	mov 	eax,[esi]
	rawptr	eax,0,ecx
	lea 	eax,[edi+eax]
	mov 	eax,[eax]
	and 	eax,0000FFFFh
	mov 	pec2_method,eax
	
	; ------- search and fix 0x23 bytes broken packed data ------- ;
	push 	esi
	push 	edi
	push 	ecx
	
		mov 	esi,sectionbase
		add 	esi,sizeof IMAGE_SECTION_HEADER
		mov 	esi,[esi.IMAGE_SECTION_HEADER.PointerToRawData]
		lea 	esi,[esi+edi]
		
		; search!!
		xor 	ecx,ecx
		.while TRUE
			.if 	dword ptr [ecx+esi]=='rFla' && \
					word ptr [ecx+esi+04]=='ee'
					lea 	esi,[esi+ecx+08h]
					.break
			.endif
			add 	ecx,1
			.if 	ecx>isize
				add 	esp,4*3
				pop 	edi
				pop 	esi
				jmp 	@nodstmem
			.endif
		.endw
		
		mov 	edi,epptr
		
		mov 	ecx,023h
		cld
		rep 	movsb
		
	pop 	ecx
	pop 	edi
	pop 	esi
	
	mov 	ecx,sectionbase
	mov 	eax,[ecx.IMAGE_SECTION_HEADER.PointerToRawData]
	lea 	esi,[edi+eax]
	
	mov 	eax,pec2_method
	.if 		ax == 0E84h		; <-- aPLib  ;
		
		mov 	eax,[ecx.IMAGE_SECTION_HEADER.Misc.VirtualSize]
		add 	eax,01000h
		mov 	dstmemsize,eax
		valloc 	eax
		test 	eax,eax
		.if	!zero?
			mov 	edi,eax
			mov 	dstmem,eax
			
			call 	PEC2_unpack_aplib
			.if 	eax
				mov2 	retv,dstmem
			.else
				vfree 	dstmem
				mov 	dstmem,0
			.endif
		.endif
		
	.elseif 	ax == 0E108h 	; <-- LZMA  ;
		
		lodsd
		mov 	pec2lzma1,eax
		
		; ------- build pec2 lzma stub ------- ;
		movzx 	eax,byte ptr [esi]
		mov 	ecx,9
		cdq
		idiv 	ecx
		movzx 	eax,al
		mov		ecx,edx
		cdq
		idiv 	edi
		mov 	pec2_bs[0],ecx
		mov 	pec2_bs[8],eax
		mov 	eax,edx
		mov 	pec2_bs[4],eax
		lea 	eax,pec2_bs
		push 	eax
		
		valloc 	4*030739h
		test 	eax,eax
		.if 	!zero?
			push 	eax
			mov 	workmem,eax
			
			mov 	ecx,sectionbase
			mov 	eax,[ecx.IMAGE_SECTION_HEADER.Misc.VirtualSize]
			add 	eax,01000h
			mov 	dstmemsize,eax
			valloc 	eax
			test 	eax,eax
			.if 	!zero?
				push 	eax
				mov 	dstmem,eax
				
				add 	esi,05h
				push 	esi
				
				call 	PEC2_unpack_lzma
				.if 	eax
					mov2 	retv,dstmem
				.else
					vfree 	dstmem
					mov 	dstmem,0
				.endif
			.endif
			vfree 	workmem
			mov 	workmem,0
		.endif
	.endif
	
@nodstmem:
	
	SehTrap 	__pec2unp
	SehEnd 		__pec2unp
	
	vfree 	srcmem
	
	mov 	eax,workmem
	.if 	eax
		vfree 	eax
	.endif
	mov 	eax,dstmem
	.if 	eax	&& !retv
		vfree 	eax
	.endif
	.if 	retv
		mov 	eax,retv
		mov 	ecx,dstmemsize
	.endif
	
	ret

pecompact_unpack_all endp




