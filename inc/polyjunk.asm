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


;-------------------------------------- polyjunk.asm ----------------------------------------;

.code

align 16

gencode proc operand:DWORD
	
	
	
	ret

gencode endp

align 16

FillJunk proc uses edi esi
	LOCAL 	tmp:DWORD
	
	lea 	edi,AnsavInitFirst
	push 	edi
	mov 	esi,AnsavInitFirstSize
	invoke 	VirtualProtect,edi,esi,PAGE_READWRITE,offset brw
	mov 	ecx,esi
	shr 	ecx,2
	@lp:
		push 	ecx
		push	10000
		call 	Random
		shl 	eax,16
		xor 	ax,cx
		stosd
		pop 	ecx
	loop 	@lp
	pop 	edi
	invoke 	VirtualProtect,edi,esi,brw,ADDR tmp
	
	ret

FillJunk endp

