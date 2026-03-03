# Diagnóstico Completo de Rede - MTU e IPv6

Ferramenta unificada em Python para auditoria de MTU, diagnóstico IPv6 e testes de performance de rede.

## 🚀 Recursos

- **Auditoria de MTU**: Encontra o MTU ideal para IPv4 e IPv6 usando busca binária
- **Diagnóstico IPv6**: Verifica stack, endereços globais, DNS, conectividade e rota
- **Testes de Performance**: Mede throughput estimado e jitter da conexão
- **Menu Interativo**: Interface simples para escolher testes
- **CLI Completa**: Argumentos de linha de comando para automação
- **Exportação**: Salva relatórios em JSON para análise posterior
- **Multiplataforma**: Funciona em Windows, Linux e macOS

## 📋 Requisitos

- Python 3.7+
- Sem dependências externas (apenas biblioteca padrão)
- Permissões de administrador podem ser necessárias para alguns testes

## 🔧 Instalação

```bash
# Clone ou copie os arquivos para seu diretório
cd diagnotico-mtu

# (Opcional) Criar ambiente virtual
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

## 💻 Uso

### Modo Menu Interativo (Recomendado para iniciantes)

```bash
python diagnotico_rede.py
```

O menu apresentará as opções:
1. Testar MTU (IPv4)
2. Testar MTU (IPv6)
3. Testar MTU (IPv4 + IPv6)
4. Diagnóstico Completo IPv6
5. Testes de Performance (Throughput + Jitter)
6. Diagnóstico Completo (Todos os testes)
7. Sair

### Linha de Comando (CLI)

```bash
# Testar apenas MTU IPv4
python diagnotico_rede.py --mtu-ipv4

# Testar apenas MTU IPv6
python diagnotico_rede.py --mtu-ipv6

# Testar MTU para ambos
python diagnotico_rede.py --mtu-completo

# Diagnóstico completo de IPv6
python diagnotico_rede.py --diagnostico-ipv6

# Testes de performance em um IP específico
python diagnotico_rede.py --performance 8.8.8.8

# Executar TODOS os testes e exportar relatório
python diagnotico_rede.py --completo --exportar relatorio.json

# Usar IPs customizados
python diagnotico_rede.py --mtu-completo --ipv4 1.1.1.1 --ipv6 2606:4700:4700::1111

# Saída mínima (apenas resultados)
python diagnotico_rede.py --completo --quiet

# Ver ajuda completa
python diagnotico_rede.py --help
```

### Opções de Linha de Comando

| Opção | Descrição |
|-------|-----------|
| `--ipv4 IP` | IP IPv4 para testes (padrão: 1.1.1.1) |
| `--ipv6 IP` | IP IPv6 para testes (padrão: 2606:4700:4700::1111) |
| `--mtu-ipv4` | Testar MTU apenas para IPv4 |
| `--mtu-ipv6` | Testar MTU apenas para IPv6 |
| `--mtu-completo` | Testar MTU para IPv4 e IPv6 |
| `--diagnostico-ipv6` | Executar diagnóstico completo de IPv6 |
| `--performance IP` | Testes de throughput e jitter |
| `--completo` | Executar TODOS os testes |
| `--menu` | Modo menu interativo |
| `--exportar ARQUIVO` | Exportar relatório para JSON |
| `--quiet, -q` | Saída mínima |
| `--verbose, -v` | Saída detalhada |
| `--help, -h` | Mostrar ajuda |

## 📊 Exemplo de Saída

```
============================================================
RELATÓRIO CONSOLIDADO
============================================================
Data/Hora: 2026-03-03 14:30:00
Hostname: DESKTOP-USUARIO
Sistema: Windows 10 (AMD64)
------------------------------------------------------------
RESUMO:
  Total de testes: 8
  Sucessos: 7
  Falhas: 1
  Taxa de sucesso: 87.5%
------------------------------------------------------------
RESULTADOS DETALHADOS:
  [+] MTU_IPv4_Payload (1472 bytes)
      Payload máximo encontrado via busca binária
  [+] MTU_IPv4_Total (1500 bytes)
      MTU total incluindo cabeçalho IPv4 (28 bytes)
  [-] IPv6_Endereco_Global
      Nenhum IP global
  ...
```

## 🧪 Scripts Legados

Os scripts originais ainda estão disponíveis para compatibilidade:

- `testar-mtu.py` - Teste básico de MTU
- `auditoria-mtu.py` - Auditoria de MTU IPv4/IPv6
- `diagnostico_ipv6.py` - Diagnóstico IPv6

## 📁 Estrutura de Arquivos

```
diagnotico-mtu/
├── README.md                 # Este arquivo
├── requirements.txt          # Dependências (vazio, só biblioteca padrão)
├── diagnotico_rede.py        # Ferramenta unificada (NOVO)
├── testar-mtu.py             # Script legado de MTU
├── auditoria-mtu.py          # Script legado de auditoria MTU
└── diagnostico_ipv6.py       # Script legado de diagnóstico IPv6
```

## 🔍 Como Funciona

### Busca Binária para MTU

1. Define limites inferior e superior (ex: 1100–1472 bytes)
2. Testa o valor do meio com `ping -f` (sem fragmentação)
3. Se passar, tenta valores maiores; se falhar, tenta menores
4. Calcula MTU final: `payload_máximo + cabeçalho`
   - IPv4: 28 bytes (20 IP + 8 ICMP)
   - IPv6: 48 bytes (40 IP + 8 ICMP)

### Diagnóstico IPv6 em 5 Etapas

1. **Stack do SO**: Verifica se socket IPv6 está habilitado
2. **Endereço Global (GUA)**: Busca IPs não link-local
3. **DNS AAAA**: Testa resolução de nomes via IPv6
4. **Ping Externo**: Conectividade ICMPv6
5. **Traceroute**: Identifica ponto de falha na rota

### Testes de Performance

- **Throughput**: Estimado baseado em tempo de resposta de múltiplos pings
- **Jitter**: Variação média entre latências de pacotes consecutivos
- **Classificação**:
  - < 1ms: Excelente
  - < 5ms: Bom
  - < 10ms: Regular
  - ≥ 10ms: Ruim (instabilidade na rede)

## 🛠️ Solução de Problemas

### "Acesso negado" ou erros de permissão

Execute como administrador/root:
```bash
# Windows (PowerShell como Admin)
python diagnotico_rede.py --completo

# Linux/Mac
sudo python diagnotico_rede.py --completo
```

### "Nenhum IPv6 global encontrado"

Seu provedor ou roteador não está fornecendo prefixo IPv6 válido. Verifique:
- Se o IPv6 está habilitado no roteador
- Se seu provedor suporta IPv6 nativo
- Configurações de SLAAC/DHCPv6

### "100% de perda" no ping

Pode ser:
- Firewall bloqueando ICMP
- Rota morta (black hole)
- MTU muito alto (use o teste de MTU para verificar)

### Jitter alto (>10ms)

Indica instabilidade na rede. Possíveis causas:
- Wi-Fi com interferência
- Rede congestionada
- Problemas no provedor

## 📝 Formato do JSON Exportado

```json
{
  "data_hora": "2026-03-03 14:30:00",
  "hostname": "DESKTOP-USUARIO",
  "sistema_operacional": "Windows 10 (AMD64)",
  "resultados": [
    {
      "nome": "MTU_IPv4_Payload",
      "sucesso": true,
      "detalhes": "Payload máximo encontrado via busca binária",
      "timestamp": "2026-03-03 14:30:00",
      "valor_medido": 1472,
      "unidade": "bytes"
    }
  ],
  "resumo": {
    "total_testes": 8,
    "sucessos": 7,
    "falhas": 1,
    "taxa_sucesso": "87.5%"
  }
}
```

## 🤝 Contribuição

Sinta-se à vontade para:
- Reportar bugs
- Sugerir melhorias
- Enviar pull requests

## 📄 Licença

MIT License - Use livremente.

## 👨‍💻 Autor

Diagnóstico MTU Tools

---

**Dica rápida**: Para um diagnóstico completo, use:
```bash
python diagnotico_rede.py --completo --exportar relatorio_$(date +%Y%m%d_%H%M%S).json
```
