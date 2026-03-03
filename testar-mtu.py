import subprocess
import platform

def testar_mtu(host, payload):
    # Define o comando baseado no Sistema Operacional
    # -f (Windows) ou -M do (Linux) impede a fragmentação
    if platform.system().lower() == "windows":
        command = ["ping", host, "-f", "-l", str(payload), "-n", "1"]
    else:
        command = ["ping", host, "-M", "do", "-s", str(payload), "-c", "1"]

    try:
        output = subprocess.run(command, capture_output=True, text=True)
        # Se o código de retorno for 0, o pacote passou sem fragmentar
        return output.returncode == 0
    except Exception:
        return False

def encontrar_mtu_ideal(host="1.1.1.1", inicio=1200, fim=1472):
    print(f"--- Iniciando teste de MTU para {host} ---")
    print(f"Testando intervalo de payload: {inicio} a {fim}\n")
    
    maior_payload_sucesso = 0

    # Busca binária para ser mais rápido que testar um por um
    baixo = inicio
    alto = fim

    while baixo <= alto:
        meio = (baixo + alto) // 2
        print(f"Testando payload {meio}...", end="\r")
        
        if testar_mtu(host, meio):
            maior_payload_sucesso = meio
            baixo = meio + 1
        else:
            alto = meio - 1

    if maior_payload_sucesso > 0:
        mtu_final = maior_payload_sucesso + 28
        print(f"\n\n[RESULTADO]")
        print(f"Maior Payload sem fragmentar: {maior_payload_sucesso}")
        print(f"MTU Ideal Recomendado (Payload + 28): {mtu_final}")
    else:
        print("\n\n[ERRO] Nenhum valor no intervalo funcionou. Verifique sua conexão ou Firewall.")

if __name__ == "__main__":
    # Testamos contra o DNS da Cloudflare já que você usa WARP
    encontrar_mtu_ideal("1.1.1.1")
