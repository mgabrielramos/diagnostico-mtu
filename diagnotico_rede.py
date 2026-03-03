#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnóstico Completo de Rede - MTU e IPv6
==========================================
Ferramenta unificada para auditoria de MTU, diagnóstico IPv6 e testes de rede.

Autor: Diagnóstico MTU Tools
Licença: MIT
"""

import argparse
import csv
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


# =============================================================================
# ESTRUTURAS DE DADOS
# =============================================================================

@dataclass
class ResultadoTeste:
    """Estrutura para armazenar resultado de um teste individual."""
    nome: str
    sucesso: bool
    detalhes: str
    timestamp: str
    valor_medido: Optional[float] = None
    unidade: Optional[str] = None


@dataclass
class RelatorioCompleto:
    """Relatório consolidado de todos os testes."""
    data_hora: str
    hostname: str
    sistema_operacional: str
    resultados: list
    resumo: dict


# =============================================================================
# UTILITÁRIOS
# =============================================================================

def limpar_tela():
    """Limpa a tela do terminal."""
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')


def obter_timestamp():
    """Retorna timestamp formatado."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_encoding():
    """Obtém encoding apropriado para o sistema."""
    if platform.system().lower() == 'windows':
        return 'cp850'
    return 'utf-8'


def executar_comando(comando: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """Executa comando shell com tratamento de erro."""
    try:
        return subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding=get_encoding(),
            errors='ignore',
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(comando, -1, "", "Timeout")
    except Exception as e:
        return subprocess.CompletedProcess(comando, -1, "", str(e))


def exportar_json(relatorio: RelatorioCompleto, arquivo: str):
    """Exporta relatório para JSON."""
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(asdict(relatorio), f, indent=2, ensure_ascii=False)
    print(f"\n[+] Relatório exportado para: {arquivo}")


def exportar_csv(resultados: list, arquivo: str):
    """Exporta resultados para CSV."""
    if not resultados:
        print("[!] Nenhum resultado para exportar.")
        return
    with open(arquivo, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ResultadoTeste.__annotations__.keys())
        writer.writeheader()
        for r in resultados:
            writer.writerow(asdict(r))
    print(f"[+] Resultados exportados para: {arquivo}")


# =============================================================================
# TESTES DE MTU
# =============================================================================

def testar_payload_mtu(ip: str, tamanho: int, ipv6: bool = False) -> bool:
    """
    Testa se um pacote do tamanho especificado passa sem fragmentar.
    
    Args:
        ip: Endereço IP de destino
        tamanho: Tamanho do payload em bytes
        ipv6: Se True, usa ping IPv6
    
    Returns:
        True se o pacote passou sem fragmentar
    """
    sistema = platform.system().lower()
    
    if sistema == 'windows':
        comando = ["ping", ip, "-n", "1", "-l", str(tamanho), "-w", "1000"]
        if not ipv6:
            comando.insert(2, "-f")  # Don't Fragment
    else:  # Linux/Mac
        if ipv6:
            comando = ["ping6", "-c", "1", "-W", "1", "-s", str(tamanho), ip]
        else:
            comando = ["ping", "-c", "1", "-W", "1", "-M", "do", "-s", str(tamanho), ip]
    
    processo = executar_comando(comando, timeout=5)
    saida = processo.stdout.lower()
    
    # Verifica fragmentação
    if "fragmentado" in saida or "fragmented" in saida or "needs to be fragmented" in saida:
        return False
    
    # Verifica perda total
    if any(x in saida for x in ["100% de perda", "100% loss", "esgotado", "timed out", "inacess"]):
        return False
    
    # Verifica resposta bem-sucedida
    if "ttl=" in saida or "ttl =" in saida or "bytes from" in saida:
        return True
    
    return False


def auditar_mtu_binaria(ip: str, ipv6: bool = False, min_payload: int = 1100, 
                        max_payload: int = None, verbose: bool = True) -> dict:
    """
    Usa busca binária para encontrar o MTU ideal.
    
    Args:
        ip: Endereço IP de destino
        ipv6: Se True, usa cabeçalho IPv6
        min_payload: Payload mínimo para busca
        max_payload: Payload máximo (padrão: calculado automaticamente)
        verbose: Se True, mostra progresso
    
    Returns:
        Dicionário com payload_máximo, mtu_ideal e status
    """
    cabecalho = 48 if ipv6 else 28
    if max_payload is None:
        max_payload = 1500 - cabecalho
    
    nome_rede = "IPv6" if ipv6 else "IPv4"
    
    if verbose:
        print(f"[*] Auditoria {nome_rede} em {ip}...")
    
    melhor_payload = min_payload
    baixo = min_payload
    alto = max_payload
    iteracoes = 0
    
    while baixo <= alto:
        meio = (baixo + alto) // 2
        iteracoes += 1
        
        if verbose:
            print(f"    -> Testando {meio} bytes (iteração {iteracoes})...", end="\r")
        
        if testar_payload_mtu(ip, meio, ipv6):
            melhor_payload = meio
            baixo = meio + 1
        else:
            alto = meio - 1
    
    if verbose:
        print(f"    -> Testando {meio} bytes (iteração {iteracoes})...")
        print(f"[+] Payload máximo: {melhor_payload} bytes | MTU Ideal: {melhor_payload + cabecalho}")
    
    return {
        "payload_maximo": melhor_payload,
        "mtu_ideal": melhor_payload + cabecalho,
        "cabecalho": cabecalho,
        "iteracoes": iteracoes,
        "status": "sucesso"
    }


def teste_mtu_completo(ip: str, ipv4: bool = True, ipv6: bool = True, 
                       verbose: bool = True) -> list:
    """
    Executa auditoria de MTU para IPv4 e/ou IPv6.
    
    Returns:
        Lista de ResultadoTeste
    """
    resultados = []
    
    if ipv4:
        print("\n" + "=" * 60)
        print("AUDITORIA DE MTU - IPv4")
        print("=" * 60)
        
        try:
            resultado = auditar_mtu_binaria(ip, ipv6=False, verbose=verbose)
            resultados.append(ResultadoTeste(
                nome="MTU_IPv4_Payload",
                sucesso=True,
                detalhes=f"Payload máximo encontrado via busca binária",
                timestamp=obter_timestamp(),
                valor_medido=resultado["payload_maximo"],
                unidade="bytes"
            ))
            resultados.append(ResultadoTeste(
                nome="MTU_IPv4_Total",
                sucesso=True,
                detalhes=f"MTU total incluindo cabeçalho IPv4 (28 bytes)",
                timestamp=obter_timestamp(),
                valor_medido=resultado["mtu_ideal"],
                unidade="bytes"
            ))
        except Exception as e:
            resultados.append(ResultadoTeste(
                nome="MTU_IPv4",
                sucesso=False,
                detalhes=str(e),
                timestamp=obter_timestamp()
            ))
    
    if ipv6:
        print("\n" + "=" * 60)
        print("AUDITORIA DE MTU - IPv6")
        print("=" * 60)
        
        try:
            resultado = auditar_mtu_binaria(ip, ipv6=True, verbose=verbose)
            resultados.append(ResultadoTeste(
                nome="MTU_IPv6_Payload",
                sucesso=True,
                detalhes=f"Payload máximo encontrado via busca binária",
                timestamp=obter_timestamp(),
                valor_medido=resultado["payload_maximo"],
                unidade="bytes"
            ))
            resultados.append(ResultadoTeste(
                nome="MTU_IPv6_Total",
                sucesso=True,
                detalhes=f"MTU total incluindo cabeçalho IPv6 (48 bytes)",
                timestamp=obter_timestamp(),
                valor_medido=resultado["mtu_ideal"],
                unidade="bytes"
            ))
        except Exception as e:
            resultados.append(ResultadoTeste(
                nome="MTU_IPv6",
                sucesso=False,
                detalhes=str(e),
                timestamp=obter_timestamp()
            ))
    
    return resultados


# =============================================================================
# TESTES DE THROUGHPUT E JITTER
# =============================================================================

def teste_throughput_ping(ip: str, pacotes: int = 10, tamanho: int = 64) -> dict:
    """
    Testa throughput estimado usando ping com múltiplos pacotes.
    
    Args:
        ip: Destino do ping
        pacotes: Número de pacotes para enviar
        tamanho: Tamanho de cada pacote em bytes
    
    Returns:
        Dicionário com métricas de throughput
    """
    sistema = platform.system().lower()
    
    if sistema == 'windows':
        comando = ["ping", ip, "-n", str(pacotes), "-l", str(tamanho)]
    else:
        comando = ["ping", "-c", str(pacotes), "-s", str(tamanho), ip]
    
    processo = executar_comando(comando, timeout=pacotes * 2 + 10)
    saida = processo.stdout
    
    # Extrair tempos de resposta
    tempos = re.findall(r'tempo[=<](\d+\.?\d*)\s*ms', saida, re.IGNORECASE)
    if not tempos:
        tempos = re.findall(r'(\d+\.?\d*)\s*ms', saida)
    
    if not tempos:
        return {"sucesso": False, "erro": "Não foi possível extrair tempos de resposta"}
    
    tempos_float = [float(t) for t in tempos]
    media = sum(tempos_float) / len(tempos_float)
    min_tempo = min(tempos_float)
    max_tempo = max(tempos_float)
    
    # Calcular jitter (variação média)
    if len(tempos_float) > 1:
        variacoes = [abs(tempos_float[i] - tempos_float[i-1]) 
                    for i in range(1, len(tempos_float))]
        jitter = sum(variacoes) / len(variacoes)
    else:
        jitter = 0
    
    # Throughput estimado (bytes/segundo)
    bytes_totais = tamanho * len(tempos_float)
    tempo_total_segundos = media * len(tempos_float) / 1000
    throughput_estimado = bytes_totais / tempo_total_segundos if tempo_total_segundos > 0 else 0
    
    return {
        "sucesso": True,
        "pacotes_enviados": len(tempos_float),
        "media_ms": round(media, 2),
        "minimo_ms": round(min_tempo, 2),
        "maximo_ms": round(max_tempo, 2),
        "jitter_ms": round(jitter, 2),
        "throughput_estimado_bps": round(throughput_estimado * 8, 2),
        "throughput_estimado_kbps": round((throughput_estimado * 8) / 1000, 2)
    }


def teste_jitter_detalhado(ip: str, pacotes: int = 20) -> dict:
    """
    Teste detalhado de jitter com estatísticas completas.
    
    Args:
        ip: Destino
        pacotes: Número de pacotes
    
    Returns:
        Estatísticas completas de jitter
    """
    print(f"[*] Testando jitter com {pacotes} pacotes...")
    
    resultado = teste_throughput_ping(ip, pacotes=pacotes)
    
    if not resultado.get("sucesso"):
        return {"sucesso": False, "erro": resultado.get("erro")}
    
    # Classificação do jitter
    jitter = resultado.get("jitter_ms", 0)
    if jitter < 1:
        classificacao = "Excelente"
    elif jitter < 5:
        classificacao = "Bom"
    elif jitter < 10:
        classificacao = "Regular"
    else:
        classificacao = "Ruim - possível instabilidade na rede"
    
    resultado["classificacao_jitter"] = classificacao
    return resultado


def testes_performance(ip: str, verbose: bool = True) -> list:
    """
    Executa todos os testes de performance.
    
    Returns:
        Lista de ResultadoTeste
    """
    resultados = []
    
    print("\n" + "=" * 60)
    print("TESTES DE PERFORMANCE - THROUGHPUT E JITTER")
    print("=" * 60)
    
    # Teste de throughput
    if verbose:
        print("\n[*] Testando throughput...")
    
    try:
        throughput = teste_throughput_ping(ip, pacotes=10)
        if throughput.get("sucesso"):
            resultados.append(ResultadoTeste(
                nome="Throughput_Latencia_Media",
                sucesso=True,
                detalhes="Latência média em teste de 10 pacotes",
                timestamp=obter_timestamp(),
                valor_medido=throughput["media_ms"],
                unidade="ms"
            ))
            resultados.append(ResultadoTeste(
                nome="Throughput_Estimado",
                sucesso=True,
                detalhes="Throughput estimado baseado em pacotes ICMP",
                timestamp=obter_timestamp(),
                valor_medido=throughput["throughput_estimado_kbps"],
                unidade="kbps"
            ))
        else:
            resultados.append(ResultadoTeste(
                nome="Throughput",
                sucesso=False,
                detalhes=throughput.get("erro", "Falha desconhecida"),
                timestamp=obter_timestamp()
            ))
    except Exception as e:
        resultados.append(ResultadoTeste(
            nome="Throughput",
            sucesso=False,
            detalhes=str(e),
            timestamp=obter_timestamp()
        ))
    
    # Teste de jitter
    if verbose:
        print("[*] Testando jitter...")
    
    try:
        jitter = teste_jitter_detalhado(ip, pacotes=20)
        if jitter.get("sucesso"):
            resultados.append(ResultadoTeste(
                nome="Jitter",
                sucesso=True,
                detalhes=f"Classificação: {jitter.get('classificacao_jitter', 'N/A')}",
                timestamp=obter_timestamp(),
                valor_medido=jitter["jitter_ms"],
                unidade="ms"
            ))
        else:
            resultados.append(ResultadoTeste(
                nome="Jitter",
                sucesso=False,
                detalhes=jitter.get("erro", "Falha desconhecida"),
                timestamp=obter_timestamp()
            ))
    except Exception as e:
        resultados.append(ResultadoTeste(
            nome="Jitter",
            sucesso=False,
            detalhes=str(e),
            timestamp=obter_timestamp()
        ))
    
    return resultados


# =============================================================================
# DIAGNÓSTICO IPv6
# =============================================================================

def verificar_stack_ipv6() -> bool:
    """Verifica se a stack IPv6 está habilitada no SO."""
    print("[1] Verificando stack IPv6 no Sistema Operacional...")
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.close()
        print("    [+] Stack IPv6 ativada e respondendo.")
        return True
    except Exception:
        print("    [-] Stack IPv6 DESATIVADA.")
        return False


def buscar_ipv6_global() -> tuple:
    """
    Busca endereço IPv6 Global (GUA) no sistema.
    
    Returns:
        Tupla (tem_global, lista_de_ips)
    """
    print("[2] Procurando Endereço IPv6 Global (GUA)...")
    
    if platform.system().lower() == 'windows':
        comando = ["ipconfig"]
    else:
        comando = ["ip", "-6", "addr"]
    
    processo = executar_comando(comando)
    saida = processo.stdout
    
    # Padrão para IPv6
    if platform.system().lower() == 'windows':
        ips = re.findall(r'IPv6.*?:\s*([a-fA-F0-9:]+)', saida)
    else:
        ips = re.findall(r'inet6\s+([a-fA-F0-9:]+)', saida)
    
    # Filtrar link-local
    ips_globais = [ip for ip in ips if not ip.lower().startswith('fe80') and '::' in ip]
    
    if ips_globais:
        print(f"    [+] Endereço Global: {ips_globais[0]}")
        return True, ips_globais
    else:
        print("    [-] Nenhum IPv6 roteável encontrado (apenas link-local).")
        return False, []


def testar_dns_ipv6() -> bool:
    """Testa resolução DNS via IPv6 (registro AAAA)."""
    print("[3] Testando resolução DNS (AAAA Record)...")
    try:
        res = socket.getaddrinfo('google.com', None, socket.AF_INET6)
        ipv6_addrs = [r[4][0] for r in res]
        print(f"    [+] DNS resolveu google.com para: {ipv6_addrs[0]}")
        return True
    except socket.gaierror:
        print("    [-] Falha ao resolver DNS via IPv6.")
        return False


def testar_ping_ipv6(ip: str = "2606:4700:4700::1111") -> bool:
    """Testa conectividade ICMPv6."""
    print("[4] Testando conectividade ICMPv6...")
    
    sistema = platform.system().lower()
    if sistema == 'windows':
        comando = ["ping", "-6", "-n", "2", ip]
    else:
        comando = ["ping6", "-c", "2", ip]
    
    processo = executar_comando(comando, timeout=10)
    saida = processo.stdout.lower()
    
    if "ttl=" in saida or "ttl =" in saida or "bytes from" in saida:
        print("    [+] Ping bem-sucedido!")
        return True
    else:
        print("    [-] Ping falhou (100% de perda).")
        return False


def traceroute_ipv6(ip: str = "2606:4700:4700::1111", max_saltos: int = 8) -> list:
    """
    Executa traceroute IPv6 para mapear rota.
    
    Returns:
        Lista de saltos encontrados
    """
    print("[5] Iniciando Traceroute (máx {} saltos)...".format(max_saltos))
    
    sistema = platform.system().lower()
    if sistema == 'windows':
        comando = ["tracert", "-6", "-h", str(max_saltos), "-w", "1000", ip]
    else:
        comando = ["traceroute6", "-m", str(max_saltos), "-w", "1", ip]
    
    processo = executar_comando(comando, timeout=max_saltos * 3 + 10)
    saida = processo.stdout
    
    saltos = []
    for linha in saida.split('\n'):
        if re.match(r'^\s*\d+', linha):
            print(f"    {linha.strip()}")
            saltos.append(linha.strip())
    
    if not saltos:
        print("    [-] Não foi possível mapear a rota.")
    
    return saltos


def diagnostico_ipv6_completo(ip_alvo: str = "2606:4700:4700::1111") -> tuple:
    """
    Executa diagnóstico completo de IPv6.
    
    Returns:
        Tupla (lista_de_resultados, veredito)
    """
    resultados = []
    veredito = ""
    
    print("\n" + "=" * 60)
    print("DIAGNÓSTICO COMPLETO DE IPv6")
    print("=" * 60)
    
    # 1. Stack
    tem_stack = verificar_stack_ipv6()
    resultados.append(ResultadoTeste(
        nome="IPv6_Stack_SO",
        sucesso=tem_stack,
        detalhes="Stack IPv6 habilitada no sistema operacional",
        timestamp=obter_timestamp()
    ))
    
    if not tem_stack:
        veredito = "Causa: IPv6 desativado no adaptador de rede."
        return resultados, veredito
    
    # 2. IP Global
    tem_ip, ips = buscar_ipv6_global()
    resultados.append(ResultadoTeste(
        nome="IPv6_Endereco_Global",
        sucesso=tem_ip,
        detalhes=f"IPs encontrados: {', '.join(ips[:3])}" if ips else "Nenhum IP global",
        timestamp=obter_timestamp()
    ))
    
    # 3. DNS
    dns_ok = testar_dns_ipv6()
    resultados.append(ResultadoTeste(
        nome="IPv6_DNS_AAAA",
        sucesso=dns_ok,
        detalhes="Resolução de DNS via IPv6",
        timestamp=obter_timestamp()
    ))
    
    # 4. Ping
    ping_ok = testar_ping_ipv6(ip_alvo)
    resultados.append(ResultadoTeste(
        nome="IPv6_Ping_ICMPv6",
        sucesso=ping_ok,
        detalhes=f"Ping para {ip_alvo}",
        timestamp=obter_timestamp()
    ))
    
    # 5. Traceroute (se ping falhou)
    if not ping_ok and tem_ip:
        saltos = traceroute_ipv6(ip_alvo)
        resultados.append(ResultadoTeste(
            nome="IPv6_Traceroute",
            sucesso=len(saltos) > 0,
            detalhes=f"Saltos encontrados: {len(saltos)}",
            timestamp=obter_timestamp()
        ))
    
    # Determinar veredito
    if not tem_ip:
        veredito = "Causa: Falha de SLAAC/DHCPv6. Provedor/roteador não fornece IPv6."
    elif ping_ok:
        veredito = "Sistema IPv6 saudável!"
    else:
        veredito = "Causa: Rota Morta (Black Hole). Tráfego morre no caminho."
    
    return resultados, veredito


# =============================================================================
# RELATÓRIO E EXPORTAÇÃO
# =============================================================================

def gerar_relatorio_completo(resultados: list) -> RelatorioCompleto:
    """Gera relatório consolidado."""
    resumo = {
        "total_testes": len(resultados),
        "sucessos": sum(1 for r in resultados if r.sucesso),
        "falhas": sum(1 for r in resultados if not r.sucesso),
        "taxa_sucesso": f"{sum(1 for r in resultados if r.sucesso) / len(resultados) * 100:.1f}%" if resultados else "0%"
    }
    
    return RelatorioCompleto(
        data_hora=obter_timestamp(),
        hostname=socket.gethostname(),
        sistema_operacional=f"{platform.system()} {platform.release()} ({platform.machine()})",
        resultados=resultados,
        resumo=resumo
    )


def imprimir_relatorio(relatorio: RelatorioCompleto):
    """Imprime relatório formatado no terminal."""
    print("\n" + "=" * 60)
    print("RELATÓRIO CONSOLIDADO")
    print("=" * 60)
    print(f"Data/Hora: {relatorio.data_hora}")
    print(f"Hostname: {relatorio.hostname}")
    print(f"Sistema: {relatorio.sistema_operacional}")
    print("-" * 60)
    print("RESUMO:")
    print(f"  Total de testes: {relatorio.resumo['total_testes']}")
    print(f"  Sucessos: {relatorio.resumo['sucessos']}")
    print(f"  Falhas: {relatorio.resumo['falhas']}")
    print(f"  Taxa de sucesso: {relatorio.resumo['taxa_sucesso']}")
    print("-" * 60)
    print("RESULTADOS DETALHADOS:")
    
    for r in relatorio.resultados:
        status = "[+]" if r.sucesso else "[-]"
        valor = f"({r.valor_medido} {r.unidade})" if r.valor_medido else ""
        print(f"  {status} {r.nome} {valor}")
        print(f"      {r.detalhes}")


# =============================================================================
# MENU INTERATIVO
# =============================================================================

def menu_interativo():
    """Exibe menu interativo e processa escolhas."""
    while True:
        print("\n" + "=" * 60)
        print("DIAGNÓSTICO DE REDE - MENU PRINCIPAL")
        print("=" * 60)
        print("1. Testar MTU (IPv4)")
        print("2. Testar MTU (IPv6)")
        print("3. Testar MTU (IPv4 + IPv6)")
        print("4. Diagnóstico Completo IPv6")
        print("5. Testes de Performance (Throughput + Jitter)")
        print("6. Diagnóstico Completo (Todos os testes)")
        print("7. Sair")
        print("-" * 60)
        
        opcao = input("Escolha uma opção [1-7]: ").strip()
        
        if opcao == '1':
            ip = input("IP de destino [1.1.1.1]: ").strip() or "1.1.1.1"
            resultados = teste_mtu_completo(ip, ipv4=True, ipv6=False)
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            
        elif opcao == '2':
            ip = input("IP IPv6 de destino [2606:4700:4700::1111]: ").strip() or "2606:4700:4700::1111"
            resultados = teste_mtu_completo(ip, ipv4=False, ipv6=True)
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            
        elif opcao == '3':
            ip4 = input("IP IPv4 de destino [1.1.1.1]: ").strip() or "1.1.1.1"
            ip6 = input("IP IPv6 de destino [2606:4700:4700::1111]: ").strip() or "2606:4700:4700::1111"
            resultados = []
            resultados.extend(teste_mtu_completo(ip4, ipv4=True, ipv6=False))
            resultados.extend(teste_mtu_completo(ip6, ipv4=False, ipv6=True))
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            
        elif opcao == '4':
            ip = input("IP IPv6 de destino [2606:4700:4700::1111]: ").strip() or "2606:4700:4700::1111"
            resultados, veredito = diagnostico_ipv6_completo(ip)
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            print(f"\nVEREDITO: {veredito}")
            
        elif opcao == '5':
            ip = input("IP de destino [1.1.1.1]: ").strip() or "1.1.1.1"
            resultados = testes_performance(ip)
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            
        elif opcao == '6':
            ip4 = input("IP IPv4 de destino [1.1.1.1]: ").strip() or "1.1.1.1"
            ip6 = input("IP IPv6 de destino [2606:4700:4700::1111]: ").strip() or "2606:4700:4700::1111"
            
            print("\n>>> Executando TODOS os testes...\n")
            
            resultados = []
            
            # MTU
            resultados.extend(teste_mtu_completo(ip4, ipv4=True, ipv6=False))
            resultados.extend(teste_mtu_completo(ip6, ipv4=False, ipv6=True))
            
            # Performance
            resultados.extend(testes_performance(ip4))
            
            # IPv6
            resultados_ipv6, veredito = diagnostico_ipv6_completo(ip6)
            resultados.extend(resultados_ipv6)
            
            relatorio = gerar_relatorio_completo(resultados)
            imprimir_relatorio(relatorio)
            
            print(f"\nVEREDITO IPv6: {veredito}")
            
            # Exportar
            exportar = input("\nExportar relatório para JSON? [s/N]: ").strip().lower()
            if exportar == 's':
                nome_arquivo = f"relatorio_rede_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                exportar_json(relatorio, nome_arquivo)
            
        elif opcao == '7':
            print("\nEncerrando. Até logo!")
            break
            
        else:
            print("\nOpção inválida! Tente novamente.")


# =============================================================================
# CLI - LINHA DE COMANDO
# =============================================================================

def criar_parser() -> argparse.ArgumentParser:
    """Cria parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        description="Diagnóstico Completo de Rede - MTU e IPv6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --mtu-ipv4 1.1.1.1
  %(prog)s --mtu-ipv6 2606:4700:4700::1111
  %(prog)s --diagnostico-ipv6
  %(prog)s --performance 8.8.8.8
  %(prog)s --completo --exportar relatorio.json
  %(prog)s --menu
        """
    )
    
    # Alvos
    parser.add_argument('--ipv4', default='1.1.1.1',
                       help='IP IPv4 para testes (padrão: 1.1.1.1)')
    parser.add_argument('--ipv6', default='2606:4700:4700::1111',
                       help='IP IPv6 para testes (padrão: Cloudflare DNS)')
    
    # Modos de teste
    grupo_testes = parser.add_argument_group('Modos de Teste')
    grupo_testes.add_argument('--mtu-ipv4', action='store_true',
                             help='Testar MTU apenas para IPv4')
    grupo_testes.add_argument('--mtu-ipv6', action='store_true',
                             help='Testar MTU apenas para IPv6')
    grupo_testes.add_argument('--mtu-completo', action='store_true',
                             help='Testar MTU para IPv4 e IPv6')
    grupo_testes.add_argument('--diagnostico-ipv6', action='store_true',
                             help='Executar diagnóstico completo de IPv6')
    grupo_testes.add_argument('--performance', metavar='IP',
                             help='Testes de throughput e jitter')
    grupo_testes.add_argument('--completo', action='store_true',
                             help='Executar TODOS os testes')
    grupo_testes.add_argument('--menu', action='store_true',
                             help='Modo menu interativo')
    
    # Opções
    parser.add_argument('--exportar', metavar='ARQUIVO',
                       help='Exportar relatório para JSON')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Saída mínima (apenas resultados)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Saída detalhada')
    
    return parser


def processar_cli(args: argparse.Namespace):
    """Processa argumentos CLI e executa testes."""
    resultados = []
    veredito = None
    
    quiet = args.quiet
    verbose = args.verbose or args.completo
    
    # MTU IPv4
    if args.mtu_ipv4 or args.mtu_completo:
        if not quiet:
            print("\n>>> Teste MTU IPv4\n")
        resultados.extend(teste_mtu_completo(args.ipv4, ipv4=True, ipv6=False, verbose=verbose))
    
    # MTU IPv6
    if args.mtu_ipv6 or args.mtu_completo:
        if not quiet:
            print("\n>>> Teste MTU IPv6\n")
        resultados.extend(teste_mtu_completo(args.ipv6, ipv4=False, ipv6=True, verbose=verbose))
    
    # Diagnóstico IPv6
    if args.diagnostico_ipv6 or args.completo:
        if not quiet:
            print("\n>>> Diagnóstico IPv6\n")
        resultados_ipv6, veredito = diagnostico_ipv6_completo(args.ipv6)
        resultados.extend(resultados_ipv6)
    
    # Performance
    if args.performance or args.completo:
        ip_perf = args.performance if args.performance else args.ipv4
        if not quiet:
            print(f"\n>>> Testes de Performance ({ip_perf})\n")
        resultados.extend(testes_performance(ip_perf, verbose=verbose))
    
    # Se nenhum teste específico, mostrar menu
    if not resultados:
        menu_interativo()
        return
    
    # Gerar e imprimir relatório
    relatorio = gerar_relatorio_completo(resultados)
    
    if not quiet:
        imprimir_relatorio(relatorio)
        
        if veredito:
            print(f"\nVEREDITO: {veredito}")
    
    # Exportar
    if args.exportar:
        exportar_json(relatorio, args.exportar)


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Ponto de entrada principal."""
    parser = criar_parser()
    args = parser.parse_args()
    
    # Modo menu ou CLI
    if args.menu or (len(sys.argv) == 1):
        menu_interativo()
    else:
        processar_cli(args)


if __name__ == "__main__":
    main()
