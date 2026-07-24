# GUARDIAN EDR PLATFORM 🛡️
## Volume 12 — Manual do Administrador do SOC & Operação de Campo
**Versão:** 1.0.0  
**Público-Alvo:** Analistas de Segurança, Operadores de SOC & Admins de TI  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Guia Operacional do Analista de SOC](#capítulo-1--guia-operacional-do-analista-de-soc)
2. [Capítulo 2 — Triagem de Alertas & Threat Hunting](#capítulo-2--triagem-de-alertas--threat-hunting)
3. [Capítulo 3 — Execução de Resposta a Incidentes (Playbooks)](#capítulo-3--execução-de-resposta-a-incidentes-playbooks)
4. [Capítulo 4 — Manutenção Preventiva do Servidor](#capítulo-4--manutenção-preventiva-do-servidor)

---

## Capítulo 1 — Guia Operacional do Analista de SOC

O analista de SOC deve manter o **Guardian Console** aberto durante seu turno:
- **Painel Geral:** Verificar o total de endpoints conectados, contagem de ativos online e alertas pendentes.
- **Identificação de Desvios:**Endpoints sinalizados como `warning` possuem métricas de CPU/RAM acima dos limites operacionais ou geraram avisos de segurança.

---

## Capítulo 2 — Triagem de Alertas & Threat Hunting

Ao receber um alerta no painel:
1. Clique no alerta para visualizar os detalhes técnicos (PID, nome do executável, caminho no sistema, usuário).
2. Copie o **Hash SHA-256** do processo e consulte em bases de inteligência de ameaças (VirusTotal / AlienVault OTX).
3. Navegue até a aba **Inspector de Conexões de Rede** para verificar se o processo tentou estabelecer sockets com IPs externos não confiáveis.

---

## Capítulo 3 — Execução de Resposta a Incidentes (Playbooks)

### 3.1 Playbook A: Confirmação de Execução Maliciosa (Ransomware / RAT)
- **Passo 1:** Clique em **"Kill PID"** para interromper o processo imediatamente.
- **Passo 2:** Clique em **"Isolar Host da Rede"** para impedir que a infecção se alastre para outros computadores da rede interna.
- **Passo 3:** Solicite à equipe de campo a remoção do malware e a coleta da imagem de memória.
- **Passo 4:** Após a desinfecção, clique em desativar isolamento para reconectar a máquina à rede corporativa.

---

## Capítulo 4 — Manutenção Preventiva do Servidor

- **Backup do Banco PostgreSQL:** Executar diariamente `pg_dump -U guardian_admin guardian_edr > backup_$(date +%Y%m%d).sql`.
- **Monitoramento de Espaço:** Assegurar que o volume de logs do PostgreSQL e do Redis permaneça dentro da cota de armazenamento alocada.
