import subprocess
import socket
import re

def verificar_suporte_so():
    print("[1] Verificando stack IPv6 no Sistema Operacional...")
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.close()
        print("    [+] Stack IPv6 ativada e respondendo no Windows.")
        return True
    except Exception:
        print("    [-] Stack IPv6 DESATIVADA na placa de rede.")
        return False

def buscar_ip_global():
    print("[2] Procurando Endereço IPv6 Global (GUA)...")
    comando = ["ipconfig"]
    processo = subprocess.run(comando, capture_output=True, text=True, encoding='cp850', errors='ignore')
    
    # Busca qualquer endereço IPv6 no ipconfig
    ips = re.findall(r'IPv6.*?:\s*([a-fA-F0-9:]+)', processo.stdout)
    
    # Filtra ignorando os endereços Link-Local (fe80::)
    ips_globais = [ip for ip in ips if not ip.lower().startswith('fe80') and '::' in ip]
    
    if ips_globais:
        print(f"    [+] Endereço Global atribuído: {ips_globais[0]}")
        return True
    else:
        print("    [-] Nenhum endereço IPv6 roteável encontrado.")
        print("    [!] Você só possui IPs locais (fe80::). Seu roteador não entregou um prefixo válido.")
        return False

def testar_dns_ipv6():
    print("[3] Testando resolução de DNS (AAAA Record)...")
    try:
        res = socket.getaddrinfo('google.com', None, socket.AF_INET6)
        ipv6_addrs = [r[4][0] for r in res]
        print(f"    [+] DNS resolveu google.com para: {ipv6_addrs[0]}")
        return True
    except socket.gaierror:
        print("    [-] Falha ao resolver DNS via IPv6.")
        return False

def testar_ping_externo():
    print("[4] Testando conectividade ICMPv6 (Ping Cloudflare)...")
    comando = ["ping", "-6", "-n", "2", "2606:4700:4700::1111"]
    processo = subprocess.run(comando, capture_output=True, text=True, encoding='cp850', errors='ignore')
    
    if "ttl=" in processo.stdout.lower() or "ttl =" in processo.stdout.lower():
        print("    [+] Ping com sucesso! O tráfego de saída e entrada está fluindo.")
        return True
    else:
        print("    [-] Ping falhou (100% de perda ou falha geral).")
        return False

def mapear_rota_morta():
    print("[5] Iniciando Traceroute (Máx 8 saltos) para encontrar o ponto de falha...")
    comando = ["tracert", "-6", "-h", "8", "-w", "1000", "2606:4700:4700::1111"]
    processo = subprocess.run(comando, capture_output=True, text=True, encoding='cp850', errors='ignore')
    
    linhas = processo.stdout.split('\n')
    saltos_encontrados = False
    
    for linha in linhas:
        # Pega apenas as linhas que começam com o número do salto
        if re.match(r'^\s*\d+', linha):
            print(f"    {linha.strip()}")
            saltos_encontrados = True
            
    if not saltos_encontrados:
        print("    [-] Falha fatal: O Windows nem conseguiu iniciar o roteamento.")

if __name__ == "__main__":
    print("-" * 60)
    print("AUDITORIA E DIAGNÓSTICO PROFUNDO DE IPv6")
    print("-" * 60)
    
    tem_stack = verificar_suporte_so()
    if tem_stack:
        tem_ip = buscar_ip_global()
        testar_dns_ipv6()
        consegue_pingar = testar_ping_externo()
        
        if not consegue_pingar and tem_ip:
            mapear_rota_morta()
            
    print("-" * 60)
    print("VEREDITO DO SISTEMA:")
    if not tem_stack:
        print("-> Causa: IPv6 desativado no adaptador de rede do Windows.")
    elif not tem_ip:
        print("-> Causa: Falha de SLAAC/DHCPv6. Seu provedor ou roteador não está fornecendo internet IPv6.")
    elif consegue_pingar:
        print("-> Sistema Saudável! O problema anterior era apenas o script batendo no limite de MTU.")
    else:
        print("-> Causa: Rota Morta (Black Hole). Você tem um IP, mas o tráfego morre no meio do caminho.")
        print("   Dica: Olhe o Traceroute acima. Se morrer no salto 1, o bloqueio é no seu Roteador.")
        print("   Se morrer no salto 2 ou 3, o problema é na infraestrutura da sua Operadora.")
    print("-" * 60)