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


; ------- rtg.asm ------- ;
; for ansav guard

.code


ProcessThisMessage proc wParam:DWORD,lParam:DWORD
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lTFI:THREATFULLINFO
	LOCAL 	retv:DWORD
	
	mov 	retv,0
	 
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	invoke 	MyZeroMemory,ADDR lTFI,sizeof THREATFULLINFO
	
	invoke 	OpenProcess,PROCESS_VM_READ,0,lParam
	.if 	eax
		mov 	ebx,eax
		
		invoke 	ReadProcessMemory,ebx,wParam,ADDR lBuff,MAX_PATH,ADDR brw
		
		.if 	lBuff[0]!=0 && lBuff[0]!='\'
			invoke CheckThisFile,ADDR lBuff,ADDR lTFI ;,1
			.if 	eax
				mov 	retv,12345678h
			.endif
		.endif
		
		invoke 	CloseHandle,ebx
	.endif
	
	mov 	eax,retv
	ret

ProcessThisMessage endp