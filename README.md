# Scanner API Pro

Um Scanner de Vulnerabilidades completo focado em APIs modernas, com integração de IA para análises avançadas. Este projeto identifica falhas de segurança críticas (Broken Authentication, IDOR, Injection, XSS, SSRF e mais) seguindo as recomendações da OWASP API Top 10.

## Estrutura do Projeto

O projeto segue uma arquitetura baseada em microserviços gerenciados pelo `docker-compose`:

- `app/`: Aplicação Python baseada em FastAPI que orquestra os Scans.
  - `core/`: Motor assíncrono do scanner e integração de OAST.
  - `modules/`: Módulos de vulnerabilidades (`auth`, `sqli`, `xss`, `idor`, etc.).
  - `ai/`: Integração com o Ollama para análise de IA.
  - `reports/`: Geração de relatórios nos formatos HTML e PDF.
- `docker-compose.yml`: Orquestração completa de Celery, Redis, Grafana, Nginx, etc.
- `grafana/` & `prometheus/`: Configurações de monitoramento.
- `.env.example`: Template de variáveis de ambiente.

*Nota: Optamos por manter a estrutura original da API em Python (baseada no padrão da comunidade FastAPI), no qual componentes como rotas (`api.py`), workers (`celery_app.py`) e regras de negócio ficam centralizados. Dividir em uma estrutura MVC clássica (como Node.js) quebraria a compatibilidade do backend com os workers Celery.*

## Tecnologias Utilizadas

- **FastAPI**: Backend da API REST.
- **Celery & Redis**: Filas de processamento assíncrono para os escaneamentos longos.
- **Docker & Docker Compose**: Orquestração e conteinerização.
- **Prometheus & Grafana**: Telemetria e Dashboard em tempo real.
- **Ollama**: Análises avançadas de vulnerabilidades utilizando LLM rodando localmente (Privacidade garantida).

## Como Instalar

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/sempicanha001-cyber/scanner-api.git
   cd scanner-api
   ```

2. **Configure as Variáveis de Ambiente:**
   ```bash
   cp .env.example .env
   # Edite o arquivo .env com suas configurações e chaves secretas.
   ```

3. **Inicie os containers:**
   ```bash
   docker compose up -d
   ```

## Como Rodar Localmente (Desenvolvimento)

Para rodar fora do Docker durante o desenvolvimento:
1. Crie e ative um ambiente virtual.
2. Instale as dependências: `pip install -r app/requirements.txt`
3. Suba uma instância local do Redis.
4. Execute o Celery Worker: `cd app && celery -A celery_app worker --loglevel=info -Q scans`
5. Em outro terminal, suba a API: `cd app && uvicorn api:app --reload`

## Deploy em Produção

1. Altere o `SCANNER_API_KEY` e senhas do Grafana/Flower no `.env` para valores fortes.
2. Em um servidor (VPS, AWS EC2, etc.), certifique-se de que portas externas (ex: 6379, 9090) estão devidamente bloqueadas via firewall.
3. Suba o ambiente via Docker Compose ou adapte os arquivos para um cluster Kubernetes.

---

> **Isenção de Responsabilidade:** Este software foi criado para fins educacionais e auditorias de segurança autorizadas. O(s) autor(es) não se responsabilizam pelo mau uso da ferramenta.
