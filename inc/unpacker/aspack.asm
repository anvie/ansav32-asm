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
;	ASPack section unpacker written by anvie based ASPack DynLoader
;
;
;

;-------------------------------------- CODE ----------------------------------------;
.data
	aspackdata dd 0 	; <-- sangat dibutuhkan! jangan dirubah!
.code

align 16
unspk_00427748 proc ; in:dword                             

        push    ecx
        mov     edx, ecx
        push    esi
        mov     ecx, 8
        push    edi
        cmp     dword ptr [edx+4], ecx
        jb      unspk_0042778c
        push    ebx
        mov     esi, -8

unspk_0042775d:

        mov     eax, dword ptr [edx]
        mov     bl, byte ptr [eax]
        inc     eax
        mov     byte ptr [esp+0ch], bl
        mov     dword ptr [edx], eax
        mov     eax, dword ptr [edx+8]
        mov     edi, dword ptr [esp+0ch]
        shl     eax, 8
        and     edi, 0ffh
        or      eax, edi
        mov     edi, dword ptr [edx+4]
        add     edi, esi
        mov     dword ptr [edx+8], eax
        mov     eax, edi
        mov     dword ptr [edx+4], edi
        cmp     eax, ecx
        jnb     unspk_0042775d
        pop     ebx

unspk_0042778c:

        mov     esi, dword ptr [edx+4]
        mov     eax, dword ptr [edx+8]
        mov     edi, dword ptr [esp+010h]
        sub     ecx, esi
        shr     eax, cl
        mov     ecx, 018h
        sub     ecx, edi
        and     eax, 0ffffffh
        shr     eax, cl
        add     esi, edi
        pop     edi
        mov     dword ptr [edx+4], esi
        pop     esi
        pop     ecx
        retn    4                            
unspk_00427748 endp

align 16
unspk_004277b3 proc  ; in1:dword, in2:dword   

        mov     eax, dword ptr [esp+4]
        mov     edx, dword ptr [esp+8]
        mov     dword ptr [ecx+084h], eax
        mov     dword ptr [ecx+088h], edx
        lea     eax, dword ptr [edx+eax*4]
        mov     dword ptr [ecx+08ch], eax
        add     eax, 0100h
        retn    8                            
unspk_004277b3 endp

align 16
unspk_004277d8 proc  ; in:dword                           

        sub     esp, 098h
        push    ebx
        push    ebp
        push    esi
        mov     edx, ecx
        push    edi
        mov     ecx, 0fh
        mov     ebp, dword ptr [edx+084h]
        xor     eax, eax
        lea     edi, dword ptr [esp+02ch]
        xor     esi, esi
        rep     stos dword ptr es:[edi]
        mov     edi, dword ptr [esp+0ach]
        cmp     ebp, esi
        mov     dword ptr [esp+020h], edx
        jbe     unspk_0042781d

unspk_00427808:

        xor     ecx, ecx
        mov     cl, byte ptr [eax+edi]
        mov     ebx, dword ptr [esp+ecx*4+028h]
        lea     ecx, dword ptr [esp+ecx*4+028h]
        inc     ebx
        inc     eax
        cmp     eax, ebp
        mov     dword ptr [ecx], ebx
        jb      unspk_00427808

unspk_0042781d:

        mov     ecx, 017h
        mov     dword ptr [esp+028h], esi
        mov     dword ptr [edx+4], esi
        mov     dword ptr [edx+044h], esi
        mov     dword ptr [esp+068h], esi
        xor     edi, edi
        mov     dword ptr [esp+01ch], esi
        mov     dword ptr [esp+010h], 1
        mov     dword ptr [esp+018h], ecx
        lea     ebp, dword ptr [edx+8]
        mov     dword ptr [esp+014h], esi

unspk_00427849:

        mov     eax, dword ptr [esp+esi+02ch]
        shl     eax, cl
        add     edi, eax
        cmp     edi, 01000000h
        mov     dword ptr [esp+024h], edi
        ja      unspk_004278ef
        mov     eax, dword ptr [esp+esi+028h]
        mov     dword ptr [ebp], edi
        ;mov     ebx, [arg.14]
		MOV     EBX, DWORD PTR [EBP+03Ch]
        add     eax, ebx
        cmp     ecx, 010h
		MOV     DWORD PTR [EBP+040h], EAX
        mov     dword ptr [esp+esi+06ch], eax
        jl      unspk_004278c6
        mov     esi, dword ptr [ebp]
        mov     eax, dword ptr [esp+010h]
        mov     ebx, dword ptr [esp+01ch]
        mov     edi, dword ptr [edx+08ch]
        shr     esi, 010h
        mov     ecx, esi
        and     eax, 0ffh
        sub     ecx, ebx
        add     edi, ebx
        mov     bl, al
        mov     edx, ecx
        mov     bh, bl
        mov     dword ptr [esp+01ch], esi
        mov     eax, ebx
        mov     esi, dword ptr [esp+014h]
        shl     eax, 010h
        mov     ax, bx
        shr     ecx, 2
        rep     stos dword ptr es:[edi]
        mov     ecx, edx
        mov     edx, dword ptr [esp+020h]
        and     ecx, 3
        rep     stos byte ptr es:[edi]
        mov     edi, dword ptr [esp+024h]
        mov     ecx, dword ptr [esp+018h]

unspk_004278c6:

        mov     eax, dword ptr [esp+010h]
        add     esi, 4
        inc     eax
        dec     ecx
        add     ebp, 4
        cmp     ecx, 9
        mov     dword ptr [esp+010h], eax
        mov     dword ptr [esp+018h], ecx
        mov     dword ptr [esp+014h], esi
        jge     unspk_00427849
        cmp     edi, 01000000h
        je      unspk_004278fe

unspk_004278ef:

        pop     edi
        pop     esi
        pop     ebp
        xor     al, al
        pop     ebx
        add     esp, 098h
        retn    4

unspk_004278fe:

        mov     eax, dword ptr [edx+084h]
        xor     ecx, ecx
        test    eax, eax
        jbe     unspk_00427945
        mov     esi, dword ptr [esp+0ach]

unspk_00427911:

        mov     al, byte ptr [ecx+esi]
        test    al, al
        je      unspk_0042793a
        mov     edi, dword ptr [edx+088h]
        and     eax, 0ffh
        mov     eax, dword ptr [esp+eax*4+068h]
        mov     dword ptr [edi+eax*4], ecx
        xor     eax, eax
        mov     al, byte ptr [ecx+esi]
        mov     edi, dword ptr [esp+eax*4+068h]
        lea     eax, dword ptr [esp+eax*4+068h]
        inc     edi
        mov     dword ptr [eax], edi

unspk_0042793a:

        mov     eax, dword ptr [edx+084h]
        inc     ecx
        cmp     ecx, eax
        jb      unspk_00427911

unspk_00427945:

        pop     edi
        pop     esi
        pop     ebp
        mov     al, 1
        pop     ebx
        add     esp, 098h
        retn    4                            
unspk_004277d8  endp

align 16
unspk_00427954 proc                              

        push    ecx
        push    ebx
        push    esi
        mov     esi, ecx
        push    edi
        mov     eax, dword ptr [esi]
        cmp     dword ptr [eax+4], 8
        jb      unspk_00427992

unspk_00427962:

        mov     ecx, dword ptr [eax]
        mov     dl, byte ptr [ecx]
        inc     ecx
        mov     byte ptr [esp+0ch], dl
        mov     dword ptr [eax], ecx
        mov     ecx, dword ptr [eax+8]
        mov     edx, dword ptr [esp+0ch]
        shl     ecx, 8
        and     edx, 0ffh
        or      ecx, edx
        mov     edx, dword ptr [eax+4]
        add     edx, -8
        mov     dword ptr [eax+8], ecx
        mov     ecx, edx
        mov     dword ptr [eax+4], edx
        cmp     ecx, 8
        jnb     unspk_00427962

unspk_00427992:

        mov     edx, dword ptr [eax+4]
        mov     eax, dword ptr [eax+8]
        mov     ecx, 8
        sub     ecx, edx
        shr     eax, cl
        mov     ecx, dword ptr [esi+024h]
        and     eax, 0fffe00h
        cmp     eax, ecx
        jnb     unspk_004279c1
        mov     edx, dword ptr [esi+08ch]
        mov     ecx, eax
        shr     ecx, 010h
        xor     ebx, ebx
        mov     bl, byte ptr [ecx+edx]
        mov     edx, ebx
        jmp     unspk_004279fc

unspk_004279c1:

        cmp     eax, dword ptr [esi+02ch]
        jnb     unspk_004279d0
        cmp     eax, dword ptr [esi+028h]
        sbb     edx, edx
        add     edx, 0ah
        jmp     unspk_004279fc

unspk_004279d0:

        cmp     eax, dword ptr [esi+030h]
        jnb     unspk_004279dc
        mov     edx, 0bh
        jmp     unspk_004279fc

unspk_004279dc:

        cmp     eax, dword ptr [esi+034h]
        jnb     unspk_004279e8
        mov     edx, 0ch
        jmp     unspk_004279fc

unspk_004279e8:

        cmp     eax, dword ptr [esi+038h]
        jnb     unspk_004279f4
        mov     edx, 0dh
        jmp     unspk_004279fc

unspk_004279f4:

        cmp     eax, dword ptr [esi+03ch]
        sbb     edx, edx
        add     edx, 0fh

unspk_004279fc:

        mov     ecx, dword ptr [esi]
        mov     edi, dword ptr [ecx+4]
        add     edi, edx
        mov     dword ptr [ecx+4], edi
        mov     ebx, dword ptr [esi+edx*4]
        mov     ecx, 018h
        sub     eax, ebx
        sub     ecx, edx
        pop     edi
        shr     eax, cl
        mov     ecx, dword ptr [esi+edx*4+044h]
        add     eax, ecx
        mov     ecx, dword ptr [esi+088h]
        pop     esi
        pop     ebx
        mov     eax, dword ptr [ecx+eax*4]
        pop     ecx
        retn                                 
unspk_00427954 endp

align 16
unaspack_init proc ; in:dword                             

        push    ebx
        push    esi
        push    edi
        mov     edi, ecx
        xor     edx, edx
        xor     eax, eax
        lea     esi, dword ptr [edi+0268h]

unspk_00427a37:

        mov     dword ptr [esi], edx
        push    esi
        call    unspk_00427c96
        mov     cl, byte ptr [eax+esi+044403ah]
        pop     esi
        mov     ebx, 1
        add     esi, 4
        shl     ebx, cl
        add     edx, ebx
        inc     eax
        cmp     eax, 03ah
        jb      unspk_00427a37
        mov     eax, dword ptr [esp+010h]
        lea     ecx, dword ptr [edi+010h]
        push    eax
        push    02d1h
        call    unspk_004277b3
        push    eax
        push    01ch
        lea     ecx, dword ptr [edi+0a0h]
        call    unspk_004277b3
        push    eax
        push    8
        lea     ecx, dword ptr [edi+0130h]
        call    unspk_004277b3
        push    eax
        push    013h
        lea     ecx, dword ptr [edi+01c0h]
        call    unspk_004277b3
        mov     dword ptr [edi+0260h], eax
        pop     edi
        pop     esi
        add     eax, 02f5h
        pop     ebx
        retn    4                            
unaspack_init 	endp

align 16
unspk_00427aa6 proc   ; in1:dword, in2:dword                           

        mov     eax, dword ptr [esp+8]
        mov     edx, ecx
        mov     ecx, dword ptr [esp+4]
        push    edi
        mov     dword ptr [edx], eax
        lea     eax, dword ptr [edx+4]
        mov     dword ptr [eax], ecx
        mov     dword ptr [eax+4], 020h
        mov     dword ptr [edx+010h], eax
        mov     dword ptr [edx+0a0h], eax
        mov     dword ptr [edx+0130h], eax
        mov     dword ptr [edx+01c0h], eax
        xor     eax, eax
        mov     ecx, 0bdh
        mov     dword ptr [edx+0250h], eax
        mov     dword ptr [edx+0254h], eax
        mov     dword ptr [edx+0258h], eax
        mov     edi, dword ptr [edx+0260h]
        mov     dword ptr [edx+025ch], eax
        rep     stos dword ptr es:[edi]
        mov     ecx, edx
        stos    byte ptr es:[edi]
        call    unspk_00427b07
        pop     edi
        retn    8                            
unspk_00427aa6 endp

align 16
unspk_00427b07 proc                              

        sub     esp, 030ch
        push    ebx
        mov     ebx, ecx
        push    ebp
        push    esi
        lea     ebp, dword ptr [ebx+4]
        push    edi
        push    1
        mov     ecx, ebp
        call    unspk_00427748
        test    eax, eax
        jnz     unspk_00427b31
        mov     edi, dword ptr [ebx+0260h]
        mov     ecx, 0bdh
        rep     stos dword ptr es:[edi]
        stos    byte ptr es:[edi]

unspk_00427b31:

        xor     esi, esi

unspk_00427b33:

        push    4
        mov     ecx, ebp
        call    unspk_00427748
        mov     byte ptr [esp+esi+010h], al
        inc     esi
        cmp     esi, 013h
        jb      unspk_00427b33
        lea     edi, dword ptr [ebx+01c0h]
        lea     eax, dword ptr [esp+010h]
        push    eax
        mov     ecx, edi
        call    unspk_004277d8
        test    al, al
        jnz     unspk_00427b67
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        add     esp, 030ch
        retn

unspk_00427b67:

        xor     esi, esi

unspk_00427b69:

        mov     ecx, edi
        call    unspk_00427954
        cmp     eax, 010h
        jnb     unspk_00427b8a
        mov     ecx, dword ptr [ebx+0260h]
        mov     dl, byte ptr [ecx+esi]
        add     dl, al
        and     dl, 0fh
        mov     byte ptr [esp+esi+024h], dl
        inc     esi
        jmp     unspk_00427bea

unspk_00427b8a:

        jnz     unspk_00427bb4
        push    2
        mov     ecx, ebp
        call    unspk_00427748
        add     eax, 3
        test    eax, eax
        jle     unspk_00427bea

unspk_00427b9c:

        cmp     esi, 02f5h
        jge     unspk_00427bf6
        mov     cl, byte ptr [esp+esi+023h]
        dec     eax
        mov     byte ptr [esp+esi+024h], cl
        inc     esi
        test    eax, eax
        jg      unspk_00427b9c
        jmp     unspk_00427bea

unspk_00427bb4:

        cmp     eax, 011h
        jnz     unspk_00427bc7
        push    3
        mov     ecx, ebp
        call    unspk_00427748
        add     eax, 3
        jmp     unspk_00427bd3

unspk_00427bc7:

        push    7
        mov     ecx, ebp
        call    unspk_00427748
        add     eax, 0bh

unspk_00427bd3:

        test    eax, eax
        jle     unspk_00427bea

unspk_00427bd7:

        cmp     esi, 02f5h
        jge     unspk_00427bf6
        mov     byte ptr [esp+esi+024h], 0
        inc     esi
        dec     eax
        test    eax, eax
        jg      unspk_00427bd7

unspk_00427bea:

        cmp     esi, 02f5h
        jl      unspk_00427b69

unspk_00427bf6:

        lea     edx, dword ptr [esp+024h]
        lea     ecx, dword ptr [ebx+010h]
        push    edx
        call    unspk_004277d8
        test    al, al
        jnz     unspk_00427c12
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        add     esp, 030ch
        retn

unspk_00427c12:

        lea     eax, dword ptr [esp+02f5h]
        lea     ecx, dword ptr [ebx+0a0h]
        push    eax
        call    unspk_004277d8
        test    al, al
        jnz     unspk_00427c34
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        add     esp, 030ch
        retn

unspk_00427c34:

        lea     ecx, dword ptr [esp+0311h]
        push    ecx
        lea     ecx, dword ptr [ebx+0130h]
        call    unspk_004277d8
        test    al, al
        jnz     unspk_00427c56
        pop     edi
        pop     esi
        pop     ebp
        pop     ebx
        add     esp, 030ch
        retn

unspk_00427c56:

        mov     byte ptr [ebx+0264h], 0
        xor     eax, eax

unspk_00427c5f:

        cmp     byte ptr [esp+eax+0311h], 3
        jnz     unspk_00427c71
        inc     eax
        cmp     eax, 8
        jb      unspk_00427c5f
        jmp     unspk_00427c78

unspk_00427c71:

        mov     byte ptr [ebx+0264h], 1

unspk_00427c78:

        mov     edi, dword ptr [ebx+0260h]
        lea     esi, dword ptr [esp+024h]
        mov     ecx, 02f5h
        rep     movs byte ptr es:[edi], byte ptr [esi]
        pop     edi
        pop     esi
        pop     ebp
        mov     al, 1
        pop     ebx
        add     esp, 030ch
        retn                                 
unspk_00427b07 endp

align 16
unspk_00427c96 proc                          

		; ------- fixed! fixed! ------- ;
        mov     esi, aspackdata
        sub     esi, 04445c7h
        retn                                 ; retn
        ; ------- fixed! fixed! ------- ;
		
;        call    unspk_00427c9c
;        nop
;
;unspk_00427c9c:
;
;        pop     esi
;		mov 	eax,lparam
;		lea 	esi,[eax+0712h]
		
       ; sub     esi, 04445c7h
        retn                                 
unspk_00427c96 endp

align 16
unspk_00427ca4 proc  ; in1:dword, in2:dword                            

        sub     esp, 014h
        mov     eax, dword ptr [esp+01ch]
        push    ebx
        push    ebp
        push    esi
        mov     dword ptr [eax], 0
        mov     eax, dword ptr [esp+024h]
        push    edi
        xor     edi, edi
        test    eax, eax
        mov     esi, ecx
        mov     dword ptr [esp+010h], edi
        jbe     unspk_00427f24

unspk_00427cc9:

        lea     ecx, dword ptr [esi+010h]
        call    unspk_00427954
        cmp     eax, 0100h
        jnb     unspk_00427ceb
        mov     ecx, dword ptr [esi]
        mov     byte ptr [ecx], al
        mov     ecx, dword ptr [esi]
        inc     ecx
        inc     edi
        mov     dword ptr [esi], ecx
        mov     dword ptr [esp+010h], edi
        jmp     unspk_00427f14

unspk_00427ceb:

        cmp     eax, 02d0h
        jnb     unspk_00427f09
        add     eax, -0100h
        mov     ebp, eax
        and     eax, 7
        shr     ebp, 3
        lea     edx, dword ptr [eax+2]
        cmp     eax, 7
        mov     dword ptr [esp+014h], edx
        jnz     unspk_00427da7
        lea     ecx, dword ptr [esi+0a0h]
        call    unspk_00427954
        mov     ecx, dword ptr [esi+8]
        xor     ebx, ebx
        push    esi
        call    unspk_00427c96
        mov     bl, byte ptr [eax+esi+044401eh]
        pop     esi
        cmp     ecx, 8
        jb      unspk_00427d68

unspk_00427d36:

        mov     ecx, dword ptr [esi+4]
        mov     dl, byte ptr [ecx]
        inc     ecx
        mov     byte ptr [esp+018h], dl
        mov     dword ptr [esi+4], ecx
        mov     ecx, dword ptr [esi+0ch]
        mov     edx, dword ptr [esp+018h]
        shl     ecx, 8
        and     edx, 0ffh
        or      ecx, edx
        mov     edx, dword ptr [esi+8]
        add     edx, -8
        mov     dword ptr [esi+0ch], ecx
        mov     ecx, edx
        mov     dword ptr [esi+8], edx
        cmp     ecx, 8
        jnb     unspk_00427d36

unspk_00427d68:

        mov     edi, dword ptr [esi+8]
        mov     edx, dword ptr [esi+0ch]
        mov     ecx, 8
        sub     ecx, edi
        add     edi, ebx
        shr     edx, cl
        mov     ecx, 018h
        mov     dword ptr [esi+8], edi
        sub     ecx, ebx
        and     edx, 0ffffffh
        shr     edx, cl
        xor     ecx, ecx
        push    esi
        call    unspk_00427c96
        mov     cl, byte ptr [eax+esi+0444002h]
        pop     esi
        mov     eax, dword ptr [esp+014h]
        add     ecx, edx
        add     eax, ecx
        mov     dword ptr [esp+014h], eax

unspk_00427da7:

        mov     al, byte ptr [esi+0264h]
        mov     ebx, dword ptr [esi+ebp*4+0268h]
        xor     edx, edx
        push    esi
        call    unspk_00427c96
        mov     dl, byte ptr [ebp+esi+044403ah]
        pop     esi
        test    al, al
        mov     edi, edx
        je      unspk_00427e40
        cmp     edi, 3
        jb      unspk_00427e40
        mov     eax, dword ptr [esi+8]
        lea     ebp, dword ptr [edi-3]
        cmp     eax, 8
        jb      unspk_00427e0b

unspk_00427dda:

        mov     eax, dword ptr [esi+4]
        mov     edx, dword ptr [esi+0ch]
        shl     edx, 8
        mov     cl, byte ptr [eax]
        inc     eax
        mov     byte ptr [esp+01ch], cl
        mov     ecx, dword ptr [esi+8]
        mov     dword ptr [esi+4], eax
        mov     eax, dword ptr [esp+01ch]
        and     eax, 0ffh
        add     ecx, -8
        or      edx, eax
        mov     eax, ecx
        cmp     eax, 8
        mov     dword ptr [esi+0ch], edx
        mov     dword ptr [esi+8], ecx
        jnb     unspk_00427dda

unspk_00427e0b:

        mov     eax, dword ptr [esi+8]
        mov     edi, dword ptr [esi+0ch]
        mov     ecx, 8
        sub     ecx, eax
        add     eax, ebp
        shr     edi, cl
        mov     ecx, 018h
        mov     dword ptr [esi+8], eax
        sub     ecx, ebp
        and     edi, 0ffffffh
        shr     edi, cl
        lea     ecx, dword ptr [esi+0130h]
        call    unspk_00427954
        add     eax, ebx
        lea     ebx, dword ptr [eax+edi*8]
        jmp     unspk_00427e9b

unspk_00427e40:

        cmp     dword ptr [esi+8], 8
        jb      unspk_00427e77

unspk_00427e46:

        mov     eax, dword ptr [esi+4]
        mov     edx, dword ptr [esi+0ch]
        shl     edx, 8
        mov     cl, byte ptr [eax]
        inc     eax
        mov     byte ptr [esp+020h], cl
        mov     ecx, dword ptr [esi+8]
        mov     dword ptr [esi+4], eax
        mov     eax, dword ptr [esp+020h]
        and     eax, 0ffh
        add     ecx, -8
        or      edx, eax
        mov     eax, ecx
        cmp     eax, 8
        mov     dword ptr [esi+0ch], edx
        mov     dword ptr [esi+8], ecx
        jnb     unspk_00427e46

unspk_00427e77:

        mov     edx, dword ptr [esi+8]
        mov     eax, dword ptr [esi+0ch]
        mov     ecx, 8
        sub     ecx, edx
        add     edx, edi
        shr     eax, cl
        mov     ecx, 018h
        mov     dword ptr [esi+8], edx
        sub     ecx, edi
        and     eax, 0ffffffh
        shr     eax, cl
        add     ebx, eax

unspk_00427e9b:

        cmp     ebx, 3
        jnb     unspk_00427eba
        mov     ecx, dword ptr [esi+ebx*4+0250h]
        test    ebx, ebx
        je      unspk_00427edb
        mov     edx, dword ptr [esi+0250h]
        mov     dword ptr [esi+ebx*4+0250h], edx
        jmp     unspk_00427ed5

unspk_00427eba:

        mov     eax, dword ptr [esi+0254h]
        mov     edx, dword ptr [esi+0250h]
        lea     ecx, dword ptr [ebx-3]
        mov     dword ptr [esi+0258h], eax
        mov     dword ptr [esi+0254h], edx

unspk_00427ed5:

        mov     dword ptr [esi+0250h], ecx

unspk_00427edb:

        mov     eax, dword ptr [esi]
        mov     edi, dword ptr [esp+014h]
        inc     ecx
        lea     edx, dword ptr [eax+edi]
        cmp     eax, edx
        mov     dword ptr [esi], edx
        jnb     unspk_00427efb

unspk_00427eeb:

        mov     edx, eax
        sub     edx, ecx
        inc     eax
        mov     dl, byte ptr [edx]
        mov     byte ptr [eax-1], dl
        mov     edx, dword ptr [esi]
        cmp     eax, edx
        jb      unspk_00427eeb

unspk_00427efb:

        mov     eax, dword ptr [esp+010h]
        add     eax, edi
        mov     dword ptr [esp+010h], eax
        mov     edi, eax
        jmp     unspk_00427f14

unspk_00427f09:

        mov     ecx, esi
        call    unspk_00427b07
        test    al, al
        je      unspk_00427f30

unspk_00427f14:

        cmp     edi, dword ptr [esp+028h]
        jb      unspk_00427cc9
        mov     eax, dword ptr [esp+02ch]
        mov     dword ptr [eax], edi

unspk_00427f24:

        pop     edi
        pop     esi
        pop     ebp
        mov     al, 1
        pop     ebx
        add     esp, 014h
        retn    8

unspk_00427f30:

        pop     edi
        pop     esi
        pop     ebp
        xor     al, al
        pop     ebx
        add     esp, 014h
        retn    8                            
unspk_00427ca4 endp

align 16
ASPACK_unpack proc ; IN PackedData:DWORD, memOut:DWORD, RawSize:DWORD, MemWork:DWORD 
	
        mov     eax, dword ptr [esp+010h]
        sub     esp, 0354h
        lea     ecx, dword ptr [esp+4]
        push    eax
        call    unaspack_init
        mov     ecx, dword ptr [esp+035ch]
        mov     edx, dword ptr [esp+0358h]
        push    ecx
        push    edx
        lea     ecx, dword ptr [esp+0ch]
        call    unspk_00427aa6 
        test    al, al
        jnz     unspk_004276a7
        or      eax, 0ffffffffh
        add     esp, 0354h
        retn

unspk_004276a7:

        mov     ecx, dword ptr [esp+0360h]
        lea     eax, dword ptr [esp]
        push    eax
        push    ecx
        lea     ecx, dword ptr [esp+0ch]
        call    unspk_00427ca4
        test    al, al
        jnz     unspk_004276ca
        or      eax, 0ffffffffh
        add     esp, 0354h
        retn

unspk_004276ca:

        mov     eax, dword ptr [esp]
        add     esp, 0354h
        retn    010h

ASPACK_unpack endp

align 16
aspack_unpack_all proc uses esi edi ebx ibase:DWORD, isize:DWORD
	
	LOCAL 	dstmem,scbase,sectnum,rawsize:DWORD
	LOCAL 	dstmemsize:DWORD
	LOCAL 	unpacked:DWORD
	
	; ------- seh ------- ;
	SehBegin 	__aspkunp
	
	mov 	edi,ibase
	mov 	eax,edi
	add 	ax,03ch
	add 	ax,[eax]
	sub 	ax,03ch
	
	mov 	ecx,eax
	add 	ecx,sizeof  IMAGE_NT_HEADERS
	sub 	ecx,sizeof 	IMAGE_OPTIONAL_HEADER32
	
	push 	eax
	
	movzx 	eax,[eax.IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
	add 	ecx,eax
	mov 	scbase,ecx
	mov 	eax,[esp]
	movzx 	eax,[eax.IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
	mov 	sectnum,eax
	mov 	edx,eax
	
	pop 	eax
	
	mov 	eax,sizeof IMAGE_SECTION_HEADER
	mov 	edx,sectnum
	add 	edx,-2
	mul 	edx
	add 	ecx,eax
	
	mov 	eax,[ecx.IMAGE_SECTION_HEADER.PointerToRawData]
	lea 	eax,[edi+eax+057Ch] ; get aspack header data
	m2m 	rawsize,dword ptr [eax+04h]
	.if 	rawsize>2000000
		SehPop
		xor 	eax,eax
		ret
	.endif
	lea 	eax,[eax+071Fh]
	mov 	aspackdata,eax	; need for init
	
	; ------- allocate working mem ------- ;
	valloc 	01800h
	.if 	eax
		mov 	esi,eax
		
		mov 	eax,rawsize
		mov 	dstmemsize,eax
		add 	eax,010Eh
		
		cmp 	eax,2000000
		ja 		@nx
		
		valloc 	eax
		.if 	eax
			
			mov 	dstmem,eax
			mov 	eax,scbase
			mov 	eax,[eax.IMAGE_SECTION_HEADER.PointerToRawData]
			add 	eax,edi
			mov 	ebx,eax
			
			SehBegin 	__aspunp
			
			mov 	unpacked,0
			
			push 	esi
			push 	rawsize
			push 	dstmem
			push 	ebx
			call 	ASPACK_unpack
			
			mov 	unpacked,1
			
			SehTrap 	__aspunp
			SehEnd 		__aspunp
			
			.if 	!unpacked
				vfree 	dstmem
			.endif
			
		.endif
@nx:

		vfree 	esi
	.endif
	
	SehTrap 	__aspkunp
	SehEnd 		__aspkunp
	
	xor 	eax,eax
	.if 	unpacked
		mov 	eax,dstmem
		mov 	ecx,dstmemsize
	.endif
	
	ret

aspack_unpack_all endp












