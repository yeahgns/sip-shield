🇧🇷 Português | 🇺🇸 [English](README.md)

# SIP Shield

Proteção plug-and-play, na camada de rede, para servidores Issabel/Asterisk. Bloqueia conexões vindas de fora de um país-alvo **em todas as portas**, antes que o Asterisk (ou o MySQL, ou o painel web) veja o pacote, adiciona o fail2ban como segunda camada contra força bruta, e restringe as portas de gestão (MySQL/AMI) ao localhost. Um instalador, um wizard interativo e um único comando `sip-shield` para operar tudo.

## Por que existe

Servidores VoIP expostos à internet são varridos o tempo todo por scanners SIP e tentativas de registro por força bruta, quase tudo vindo de infraestrutura sem nenhum motivo legítimo para falar com o PBX. Defesas na camada de aplicação, como o fail2ban, só reagem depois de várias tentativas falhas — ou seja, todo atacante ainda consegue sondar o servidor antes de ser bloqueado. Filtrar por país na camada de rede remove a maior parte desse tráfego logo de cara; o fail2ban cuida do que sobra, inclusive atacantes de dentro do país permitido; e o hardening de portas de gestão fecha os serviços administrativos (MySQL, Asterisk Manager Interface) que não deveriam estar na internet pública — exatamente o tipo de exposição que motivou este projeto.

## Como funciona

```
Conexão nova chega (qualquer porta)
 → loopback? / trunk? / IP confiável?      → ACCEPT
 → IP de origem no país permitido?          (ipset do RIPE NCC)
     → Não → DROP (Asterisk/MySQL/web nem veem)
     → Sim → segue
              → MySQL/AMI de fora do localhost? → DROP (hardening de gestão)
              → fail2ban observa força bruta     → bane após N falhas
```

O bloqueio GeoIP fica no topo do `INPUT` e só casa com conexões **novas**, então o tráfego já estabelecido nunca é interrompido e atacantes com fluxo UDP contínuo não escapam do ban.

## O que faz

- **GeoIP via iptables/ipset, todas as portas** — bloqueia conexões novas de fora do país-alvo em qualquer porta e protocolo. Trocar a porta SIP/PJSIP depois não exige nada.
- **Hardening de portas de gestão** — restringe MySQL (`3306`) e a Asterisk Manager Interface (`5038`) ao localhost independentemente do país, então nem um atacante nacional as alcança. Ligado por padrão; configurável.
- **fail2ban** — segunda camada, bane força bruta de qualquer lugar, inclusive do país permitido. Loopback, trunks e IPs confiáveis nunca são banidos por nenhum jail.
- **Atualização atômica** — os ranges do país são atualizados mensalmente via RIPE NCC com `ipset swap`, sem janela desprotegida; se o RIPE falhar ou devolver uma lista curta, os ranges atuais são mantidos.
- **Proteção anti-lockout** — se o IP de onde você está conectado por SSH seria bloqueado, a instalação aborta antes de mexer no firewall (force com `SIP_SHIELD_FORCE=1`).
- **Pré-ban de IPs conhecidos** (opcional) — uma lista-semente de IPs maliciosos, banidos na instalação.
- **Observabilidade** — log JSON estruturado, webhook genérico e métricas Prometheus (textfile). Tudo aditivo, tudo opcional.

## Compatibilidade

| Sistema | Testado com |
|---|---|
| CentOS 7 | Issabel 4 |
| Rocky Linux 8 | Issabel 5 |

Apenas IPv4 na versão atual.

## Instalação

```bash
git clone https://github.com/yeahgns/sip-shield.git
cd sip-shield
```

**Wizard interativo** (recomendado para um host):

```bash
sudo bash install.sh --wizard
```

O wizard pergunta o país-alvo, IPs de trunk/confiáveis/cliente, hardening de portas de gestão, webhook opcional e ajustes do fail2ban, mostra um resumo e aplica tudo.

**Não-interativo** (automação / Ansible):

```bash
export SIP_SHIELD_COUNTRY="BR"                       # obrigatório, ISO 3166-1 alpha-2
export SIP_SHIELD_TRUNK_IPS="203.0.113.10"            # provedor(es) de trunk SIP
export SIP_SHIELD_TRUSTED_IPS="198.51.100.5"          # monitoramento / máquina de gestão
sudo bash install.sh
```

O instalador é idempotente — rodar de novo (inclusive em hosts ainda no modelo antigo por porta) migra para o modelo atual sem duplicar regras. Tudo é instalado em `/opt/sip-shield`, então o clone pode ser apagado depois.

## O comando `sip-shield`

Instalado em `/usr/local/bin/sip-shield` — um ponto de entrada só, sem precisar decorar caminhos em `lib/`:

```bash
sip-shield status         # estado atual (país, ranges, drops, bans, hardening)
sip-shield update         # atualizar ranges agora e reaplicar regras
sip-shield ban <ip>       # banir um IP
sip-shield unban <ip>     # desbanir um IP
sip-shield banned         # listar IPs banidos
sip-shield test <ip>      # esse IP passaria pelo filtro GeoIP?
sip-shield ranges         # quantos ranges do país estão carregados
sip-shield rules          # mostrar as regras iptables do SIP Shield
sip-shield config         # editar config do host e lembrar de aplicar
sip-shield logs [n]       # últimas n linhas do log de bans
sip-shield help
```

Exemplo do `sip-shield status`:

```
SIP Shield
────────────────────────────────────────
Target country:         BR
Asterisk ports:         5060/udp 5061/tcp
Allowed ranges loaded:  12927
Packets dropped:        128291
Data dropped:           9.37 MB
Currently banned (f2b): 7
Total bans logged:      42
Mgmt-port hardening:    on (3306 5038)
────────────────────────────────────────
```

## Configuração

As configurações por host ficam em `/etc/sip-shield/sip-shield.conf`, criado na instalação e **nunca sobrescrito** por reinstalação. Edite direto (ou via `sip-shield config`) e aplique com `sip-shield update`.

| Chave | Significado |
|---|---|
| `SIP_SHIELD_COUNTRY` | Código ISO 3166-1 alpha-2 do país a permitir. |
| `TRUNK_IPS` | Provedor(es) de trunk/DID: liberados em tudo, nunca banidos. |
| `TRUSTED_IPS` | IPs de gestão fora do país: liberados em tudo, nunca banidos. |
| `F2B_IGNORE_IPS` | IPs fixos de cliente: nunca banidos, **mas** ainda sujeitos ao GeoIP e ao hardening de gestão. Use este, não o `TRUSTED_IPS`, para cliente. |
| `GEOIP_ALLOW_NETS` | CIDRs estrangeiros tratados como nacionais (ex.: trunk PJSIP de um provedor de mensagens). |
| `HARDEN_MGMT_PORTS` | `1` (padrão) restringe portas de gestão ao localhost; `0` desativa. |
| `MGMT_PORTS` | Portas restritas ao localhost (padrão `3306 5038`). |

Precedência: variáveis de ambiente do shell atual > arquivo de config > padrões internos. É isso que permite o mesmo código rodar interativo, via Ansible e via cron.

### Pré-ban de IPs conhecidos (opcional)

```bash
cp lib/known-ips.txt.example lib/known-ips.txt
# edite com IPs dos seus próprios logs; se o arquivo não existir, o passo é pulado
```

## Observabilidade

Três saídas aditivas — nenhuma muda a lógica de bloqueio, todas seguras de deixar desligadas.

**Prometheus** — um textfile `.prom` é escrito na instalação e atualizado a cada 5 minutos via cron. Aponte o textfile collector do node_exporter para `SIP_SHIELD_PROM_TEXTFILE_DIR` (padrão `/var/lib/sip-shield/metrics`) e o Prometheus coleta normalmente; o Grafana lê do Prometheus. Métricas: `sip_shield_geoip_dropped_packets_total`, `sip_shield_geoip_dropped_bytes_total`, `sip_shield_allowed_country_ranges`, `sip_shield_fail2ban_banned_ips`, `sip_shield_known_ips_loaded`, `sip_shield_bans_logged_total`, `sip_shield_mgmt_ports_hardened`.

**Log JSON** — cada ban/unban como um objeto JSON por linha, para qualquer log shipper/SIEM:

```json
{"timestamp":"2026-06-12T13:45:22Z","event":"ban","ip":"203.0.113.50","origin":"fail2ban"}
```

**Webhook** — POST JSON fire-and-forget em cada ban/unban (Telegram/Slack/Discord/custom). Um endpoint lento ou fora do ar nunca atrasa o ban:

```bash
export SIP_SHIELD_WEBHOOK_URL="https://seu-endpoint.example/webhook"
```

## Arquivos

| Caminho | O que é |
|---|---|
| `/opt/sip-shield/` | código instalado |
| `/usr/local/bin/sip-shield` | o comando central |
| `/etc/sip-shield/sip-shield.conf` | config do host (nunca sobrescrito) |
| `/etc/sip-shield/allowed_ranges.txt` | ranges do país baixados |
| `/etc/sip-shield/ipset.save` | snapshot do ipset para o boot |
| `/etc/sip-shield/restore.sh` | chamado pelo `rc.local` no boot |
| `/etc/cron.d/sip-shield` | atualização mensal + refresh de métricas (5 min) |
| `/var/log/sip-shield.log` | log de ban/unban |
| `/var/log/sip-shield.jsonl` | eventos JSON estruturados |

## Limitações conhecidas

- Filtro por país é um instrumento grosso: usuários legítimos viajando ou em VPN são bloqueados se não forem liberados individualmente. Troca-se um pouco de atrito por uma grande redução de superfície de ataque.
- Dados de IP-para-país (RIPE NCC aqui) não são perfeitamente precisos nem instantâneos; a atualização mensal reduz, mas não elimina, a defasagem.
- Sem breakdown de país por atacante — o projeto só sabe se a origem **está ou não** no país permitido, não de qual país veio um pacote bloqueado. Isso exigiria uma base completa de IP-para-país (ex.: MaxMind GeoLite2) em vez da lista de país único do RIPE.
- Testado em Issabel sobre CentOS 7 e Rocky Linux 8; outras distros Asterisk provavelmente pedem pequenos ajustes em `lib/detect.sh` e nas chamadas de gerenciador de pacotes.

## Licença

MIT — veja [LICENSE](LICENSE).
