    .text
    .global my_connect

my_connect: 
    mov     ip, r7
    ldr     r7, =283
    swi     #0  
    mov     r7, ip
    bx    lr
    
