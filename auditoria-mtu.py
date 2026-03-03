import subprocess

def testar_payload(ip, tamanho, ipv6=False):
    """Dispara um ping único e verifica se o pacote passou inteiro."""
    comando = ["ping", ip, "-n", "1", "-l", str(tamanho), "-w", "1000"]
    
    # O IPv4 precisa da flag -f (Don't Fragment)
    if not ipv6:
        comando.insert(2, "-f")
        
    processo = subprocess.run(comando, capture_output=True, text=True, encoding='cp850', errors='ignore')
    saida = processo.stdout.lower()
    
    # Se avisar que precisa fragmentar, falhou na hora
    if "fragmentado" in saida or "fragmented" in saida:
        return False
        
    # Se o pacote se perdeu no caminho
    if "100% de perda" in saida or "100% loss" in saida or "esgotado" in saida or "timed out" in saida or "inacess" in saida:
        return False
        
    # Se respondeu com TTL, o pacote foi e voltou com sucesso
    if "ttl=" in saida or "ttl =" in saida:
        return True
        
    return False

def auditar_mtu(ip, ipv6=False):
    """Usa busca binária para encontrar o Payload máximo e calcular o MTU ideal."""
    nome_rede = "IPv6" if ipv6 else "IPv4"
    print(f"[*] Iniciando auditoria {nome_rede} no alvo: {ip}...")
    
    # Define os limites da busca
    cabecalho = 48 if ipv6 else 28
    min_payload = 1100  # Limite mínimo seguro para o payload
    max_payload = 1500 - cabecalho # Limite máximo padrão (1472 para v4, 1452 para v6)
    
    melhor_payload = min_payload
    baixo = min_payload
    alto = max_payload
    
    # Busca binária
    while baixo <= alto:
        meio = (baixo + alto) // 2
        print(f"    -> Testando pacote de {meio} bytes...")
        
        if testar_payload(ip, meio, ipv6):
            melhor_payload = meio
            baixo = meio + 1 # Passou, vamos tentar um maior
        else:
            alto = meio - 1  # Falhou, precisa ser menor

    mtu_ideal = melhor_payload + cabecalho
    print(f"[+] SUCESSO! Payload máximo: {melhor_payload} bytes | MTU Ideal: {mtu_ideal}\n")
    return mtu_ideal

if __name__ == "__main__":
    print("-" * 50)
    print("AUDITORIA DE MTU - REDE LOCAL")
    print("-" * 50)
    
    mtu_v4 = auditar_mtu("1.1.1.1", ipv6=False)
    mtu_v6 = auditar_mtu("2606:4700:4700::1111", ipv6=True)
    
    print("-" * 50)
    print("RESUMO DA AUDITORIA:")
    print(f"-> MTU exato para IPv4: {mtu_v4}")
    print(f"-> MTU exato para IPv6: {mtu_v6}")
    print("-" * 50)