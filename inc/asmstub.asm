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


;-------------------------------------- asmstub.asm ----------------------------------------;
.data?
	reg_EAX EQU 0
	reg_ECX EQU 1
	reg_EDX EQU 2
	reg_EBX EQU 3
	reg_ESP EQU 4
	reg_EBP EQU 5
	reg_ESI EQU 6
	reg_EDI EQU 7
	
	x_INC EQU 040h
	x_DEC EQU 048h
	
	x_PUSH EQU 050h
	x_POP  EQU 058h
	
	x_PUSHAD EQU 060h
	x_POPAD EQU 061h
	
	x_NEG EQU 0F7D8h
	x_NOT EQU 0F7D0h
	
	x_SUB EQU 083E8h
	x_ADD EQU 083C0h
	
	MUTLAK_TERINFEKSI EQU 10105
	
	sset8 db ?
	eset8 db ?
	
	sset16 dw ?
	eset16 dw ?
	
	sset32 dd ?
	eset32 dd ?
	
.code