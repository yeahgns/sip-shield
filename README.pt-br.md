🇺🇸 [English](README.md) | 🇧🇷 Português

# SIP Shield

Proteção via GeoIP + fail2ban para servidores Issabel/Asterisk. Bloqueia tráfego SIP de fora de um país-alvo na camada de rede, antes do Asterisk sequer ver o pacote, e usa fail2ban como segunda linha de defesa contra tentativas de força bruta.

## Por que existe

Servidores VoIP expostos na internet pública recebem varredura SIP automatizada e tentativas de força bruta o tempo todo, boa parte vinda de infraestrutura sem motivo legítimo nenhum de falar com o PBX. Defesas de camada de aplicação, só fail2ban, entram em ação depois de um número de tentativas falhas, então todo atacante ainda consegue sondar o servidor diretamente antes de ser bloqueado. Filtrar por país na camada de rede remove a maior parte desse tráfego antes de chegar no Asterisk. O fail2ban cuida do que sobra, incluindo atacantes de dentro do país permitido.

## Como funciona

```
Requisição SIP chega
→ iptables verifica: o IP de origem é do país-alvo?
  (checado contra um ipset populado com dados do RIPE NCC)
  → Não → descartado na hora, o Asterisk nunca vê
  → Sim → encaminhado pro Asterisk
           → fail2ban monitora tentativas suspeitas
           → bane após N falhas numa janela de tempo
```

## O que faz

- **GeoIP via iptables/ipset**: bloqueia tráfego SIP de fora de um país-alvo configurável
- **fail2ban**: segunda camada, bane tentativas de força bruta de qualquer lugar, incluindo o país permitido
- **Pré-ban de IPs conhecidos** (opcional): uma lista inicial de IPs atacantes já observados, banidos na instalação
- **Atualização automática**: os ranges do país-alvo são atualizados mensalmente via RIPE NCC, já que alocações mudam com o tempo

## Compatibilidade

| Sistema | Testado com |
|---|---|
| CentOS 7 | Issabel 4 |
| Rocky Linux 8 | Issabel 5 |

A detecção de porta SIP é automática e não assume nenhuma porta específica. Funciona tanto no padrão `5060` quanto numa porta customizada.

## Instalação

```bash
git clone https://github.com/yeahgns/sip-shield.git
cd sip-shield
```

Configure seu ambiente antes de rodar (veja Configuração abaixo), depois:

```bash
sudo bash install.sh
```

## Configuração

Nada nos scripts contém IP, hostname ou nome de empresa reais. Tudo é definido via variável de ambiente antes de rodar. `SIP_SHIELD_COUNTRY` não tem valor padrão e precisa ser definida explicitamente, a instalação para com erro se ela estiver faltando, assim o país-alvo é sempre uma escolha deliberada:

```bash
export SIP_SHIELD_COUNTRY="BR"                                  # obrigatório — código de país ISO 3166-1 alpha-2 a permitir
export SIP_SHIELD_WHITELIST_IPS="203.0.113.10,203.0.113.11"      # seu(s) provedor(es) de troncos SIP, sempre permitidos
export SIP_SHIELD_MAXRETRY="5"                                  # opcional, ajuste do fail2ban
export SIP_SHIELD_FINDTIME="60"                                 # opcional, segundos
export SIP_SHIELD_BANTIME="604800"                               # opcional, segundos (padrão: 7 dias)

sudo bash install.sh
```

Se `SIP_SHIELD_WHITELIST_IPS` ficar vazio, nenhum IP fica isento das regras de GeoIP/fail2ban. Garanta que está configurado se você tem provedor de tronco SIP fora do país permitido, senão seu próprio tronco fica bloqueado.

### Pré-ban de IPs conhecidos (opcional)

`lib/known-ips.txt.example` vem com uma lista inicial de IPs já observados atacando servidores SIP em ambientes reais. É um ponto de partida, não uma blocklist mantida. Infraestrutura de atacante muda o tempo todo.

Pra habilitar essa etapa:

```bash
cp lib/known-ips.txt.example lib/known-ips.txt
# edita lib/known-ips.txt com IPs relevantes aos seus próprios logs, se quiser
```

Se `lib/known-ips.txt` não existir, a instalação pula essa etapa.

## Comandos úteis

```bash
# status do fail2ban
fail2ban-client status asterisk

# quantos ranges do país estão carregados
ipset list allowed_ranges | wc -l

# banir um IP manualmente
fail2ban-client set asterisk banip <IP>

# atualizar os ranges do país manualmente
bash lib/update.sh

# ver regras GeoIP ativas
iptables -L INPUT -n | grep allowed_ranges
```

## Atualizações

Os ranges do país-alvo são atualizados automaticamente todo dia 1 do mês às 03:00, via entrada de cron criada pelo `install.sh`. Log em `/var/log/sip-shield-update.log`.

Atualização manual:

```bash
bash lib/update.sh
```

O histórico de ban/unban é logado separadamente, em `/var/log/sip-shield.log`:

```
[2026-06-12 13:45:22] BAN ip=203.0.113.50 origin=known-ips-list
[2026-06-12 13:47:10] BAN ip=203.0.113.77 origin=fail2ban jail=asterisk
[2026-06-12 14:02:55] UNBAN ip=203.0.113.77 origin=fail2ban jail=asterisk
```

## Estrutura

```
sip-shield/
├── README.md
├── README.pt-br.md
├── install.sh
└── lib/
    ├── config.sh
    ├── detect.sh
    ├── fail2ban.sh
    ├── geoip.sh
    ├── metrics.sh
    ├── record-event.sh
    ├── stats.sh
    ├── update.sh
    └── known-ips.txt.example
```

## Observabilidade

Três saídas aditivas, nenhuma delas muda a lógica de bloqueio, e todas são seguras de deixar desativadas.

**Resumo legível pra humano**

```bash
bash lib/stats.sh
```

```
SIP Shield
────────────────────────────────────────
Target country:        BR
SIP port:               5060
Allowed ranges loaded:  12927
Packets dropped:        128291
Data dropped:           9.37 MB
Currently banned (f2b): 7
Total bans logged:      42
────────────────────────────────────────
```

**Métricas Prometheus**

Escritas automaticamente em `SIP_SHIELD_PROM_TEXTFILE_DIR` (padrão `/var/lib/sip-shield/metrics/sip_shield.prom`) na instalação, e atualizadas a cada 5 minutos via entrada de cron que o `install.sh` configura. Aponta o textfile collector do node_exporter pra esse diretório e o Prometheus pega as métricas no scrape normal dele, o Grafana então lê do Prometheus, sem integração separada com Grafana:

```bash
export SIP_SHIELD_PROM_TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"  # exemplo
```

Métricas expostas: `sip_shield_geoip_dropped_packets_total`, `sip_shield_geoip_dropped_bytes_total`, `sip_shield_allowed_country_ranges`, `sip_shield_fail2ban_banned_ips`, `sip_shield_known_ips_loaded`, `sip_shield_bans_logged_total`.

**Log JSON estruturado**

Todo ban/unban também é logado como um objeto JSON por linha, junto do log em texto já existente, pega isso com qualquer log shipper ou SIEM que consiga acompanhar um arquivo (Filebeat, Wazuh, Splunk forwarder, etc.):

```bash
export SIP_SHIELD_JSON_LOG="/var/log/sip-shield.jsonl"  # padrão mostrado
```

```json
{"timestamp":"2026-06-12T13:45:22Z","event":"ban","ip":"203.0.113.50","origin":"fail2ban"}
```

**Webhook genérico**

Dispara um POST em JSON a cada ban/unban se configurado, funciona com Telegram (via um relay compatível com `sendMessage` de um bot), webhooks de entrada do Slack, webhooks do Discord, ou qualquer endpoint customizado:

```bash
export SIP_SHIELD_WEBHOOK_URL="https://seu-endpoint.exemplo/webhook"
```

A chamada do webhook é fire-and-forget: um endpoint falho ou lento nunca bloqueia ou atrasa o ban/unban real.

## Persistência de configuração

O `install.sh` grava a configuração resolvida em `/etc/sip-shield/config.env` (permissão `600`, já que pode conter uma URL de webhook) no final de uma execução com sucesso. Isso existe porque o `lib/update.sh` (via cron) e a action de ban/unban do fail2ban não herdam variáveis de ambiente da sua sessão de terminal, sem isso, os dois falhariam silenciosamente em achar `SIP_SHIELD_COUNTRY` fora da sessão de instalação. Variável de ambiente na sessão atual sempre tem prioridade sobre esse arquivo, ele é só um fallback pra contextos não-interativos.

## Limitações conhecidas

- Filtro por país é uma ferramenta grosseira. Usuário legítimo viajando pro exterior, ou usando VPN/proxy, vai ser bloqueado a menos que seja colocado na whitelist individualmente. Isso troca um pouco de fricção de tráfego legítimo por uma redução grande de superfície de ataque, avalia se essa troca faz sentido pro seu caso.
- Dado de IP-pra-país (RIPE NCC, nessa implementação) não é perfeitamente preciso nem instantâneo. Ranges são realocados entre regiões com o tempo, por isso existe a atualização mensal, mas sempre tem alguma defasagem.
- Testado especificamente em Issabel sobre CentOS 7 e Rocky Linux 8. Outras distribuições baseadas em Asterisk provavelmente funcionam com pequenos ajustes em `lib/detect.sh` e nas chamadas de gerenciador de pacote em `install.sh`.
- Só IPv4, na versão atual.
- Sem detalhamento por país de atacante ("top países atacantes"), esse projeto só sabe se o IP de origem de um pacote *é ou não é* do país permitido, não sabe qual país um pacote bloqueado realmente veio. Isso exigiria uma base completa de IP-pra-país (ex: MaxMind GeoLite2) em vez da lista de ranges de um único país do RIPE NCC, decisão deliberada de escopo, não uma omissão.

## Licença

MIT
