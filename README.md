# API de Alteração de Senhas no Active Directory

API Django REST Framework para alteração e reset de senhas no Active Directory via LDAP/LDAPS.

## 📋 Índice

- [Características](#características)
- [Pré-requisitos](#pré-requisitos)
- [O Que Fazer Antes](#o-que-fazer-antes)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Execução](#execução)
- [Endpoints da API](#endpoints-da-api)
- [Docker](#docker)
- [Solução de Problemas](#solução-de-problemas)

## Características

- ✅ API REST com Django REST Framework
- ✅ Conexão segura via LDAPS com fallback para LDAP
- ✅ Reset de senha por administrador
- ✅ Verificação de existência de usuário
- ✅ Suporte a Docker
- ✅ Tratamento robusto de erros
- ✅ Configuração via variáveis de ambiente
- ✅ Validação de entrada de dados

## Pré-requisitos

### Software Necessário

- **Python 3.8 ou superior**
- **pip** (gerenciador de pacotes Python)
- **Git** (para clonar o repositório)
- **Acesso ao servidor Active Directory** via rede
- **Credenciais de administrador** do Active Directory

### Sistema Operacional

- Windows (recomendado, pois geralmente está no mesmo domínio)
- Linux (funciona, mas pode precisar de configuração de rede adicional)
- macOS (funciona, mas pode precisar de configuração de rede adicional)

### Conhecimento Necessário

- Noções básicas de linha de comando
- Conhecimento do seu domínio Active Directory (nome do domínio, servidor, etc.)
- Acesso de administrador ao servidor AD (para configurar LDAPS)

## O Que Fazer Antes

### 1. Configurar LDAPS no Servidor Active Directory

⚠️ **IMPORTANTE**: Para reset de senhas por administrador, é necessário usar LDAPS (conexão segura).

**Passo a passo:**

1. Copie o arquivo `EXECUTAR_ESTE_NO_SERVIDOR_AD.ps1` para o servidor Active Directory
2. Abra o PowerShell como **Administrador** no servidor AD
3. Execute o script:
   ```powershell
   .\EXECUTAR_ESTE_NO_SERVIDOR_AD.ps1
   ```
4. Aguarde a conclusão (2-5 minutos)
5. Aguarde mais **10 minutos** para ativação completa do certificado
6. Teste a conexão LDAPS (porta 636):
   ```powershell
   Test-NetConnection -ComputerName seu-servidor-ad -Port 636
   ```

**Nota**: Se não puder configurar LDAPS imediatamente, a aplicação tentará fallback automático para LDAP (porta 389), mas algumas operações podem não funcionar.

### 2. Obter Informações do Active Directory

Você precisará das seguintes informações:

- **Servidor AD**: IP ou hostname do controlador de domínio
  - Exemplo: `192.168.100.23` ou `dc.empresa.local`
- **Base DN**: Distinguished Name base do domínio
  - Exemplo: `DC=hbh,DC=local` ou `DC=empresa,DC=com`
  - Para descobrir: `Get-ADDomain` no PowerShell do servidor AD
- **Credenciais de Admin**: Usuário e senha com permissão para resetar senhas
  - Exemplo: `administrador` ou `admin.ad`
  - Deve ter permissões: "Reset Password" e "Change Password"

### 3. Verificar Conectividade de Rede

Certifique-se de que a máquina onde a aplicação será executada consegue acessar o servidor AD:

```powershell
# Windows PowerShell
Test-NetConnection -ComputerName 192.168.100.23 -Port 389  # LDAP
Test-NetConnection -ComputerName 192.168.100.23 -Port 636  # LDAPS
```

```bash
# Linux/Mac
telnet 192.168.100.23 389  # LDAP
telnet 192.168.100.23 636  # LDAPS
```

## Instalação

### Passo 1: Clonar o Repositório

```bash
git clone git@github.com:FernandoL9/ad_password_change.git
cd ad_password_change
```

### Passo 2: Criar Ambiente Virtual (Recomendado)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Passo 3: Instalar Dependências

```bash
pip install -r requirements.txt
```

As seguintes bibliotecas serão instaladas:
- `Django==5.0.6` - Framework web
- `djangorestframework==3.15.2` - API REST
- `ldap3==2.9.1` - Cliente LDAP
- `django-environ==0.11.2` - Gerenciamento de variáveis de ambiente
- `gunicorn==21.2.0` - Servidor WSGI para produção

## Configuração

### Passo 1: Criar Arquivo .env

Copie o template e edite com seus dados:

```bash
# Windows
copy ENV_TEMPLATE .env

# Linux/Mac
cp ENV_TEMPLATE .env
```

### Passo 2: Editar .env

Abra o arquivo `.env` em um editor de texto e preencha:

```env
# Django
SECRET_KEY=sua-chave-secreta-aqui-gerada-aleatoriamente
DEBUG=true
ALLOWED_HOSTS=*

# Active Directory
AD_SERVER=ldaps://192.168.100.23:636
AD_BASE_DN=DC=hbh,DC=local
LDAP_TIMEOUT=30
SSL_VERIFY=false

# Credenciais de admin (NÃO commitar este arquivo!)
AD_ADMIN_USER=administrador
AD_ADMIN_PASSWORD=sua-senha-admin
```

**Importante:**

- `AD_SERVER`: Use `ldaps://` para conexão segura ou `ldap://` para conexão simples (fallback automático)
  - LDAPS: `ldaps://192.168.100.23:636`
  - LDAP: `ldap://192.168.100.23:389`
- `AD_BASE_DN`: Substitua pelos valores do seu domínio
  - Para descobrir: No PowerShell do servidor AD: `(Get-ADDomain).DistinguishedName`
- `SSL_VERIFY`: 
  - `false` = Aceita certificados autoassinados (testes/desenvolvimento)
  - `true` = Exige certificado válido (produção)
- `SECRET_KEY`: Gere uma chave aleatória:
  ```python
  python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
  ```

### Passo 3: (Opcional) Atualizar config.py

Se for usar o modo CLI (`ad_password_change.py`), também atualize `config.py`:

```python
AD_SERVER = 'ldaps://192.168.100.23:636'
AD_BASE_DN = 'DC=hbh,DC=local'
LDAP_TIMEOUT = 30
SSL_VERIFY = False
```

⚠️ **Segurança**: Nunca commite o arquivo `.env` com credenciais reais!

## Execução

### Modo Desenvolvimento (Recomendado para testes)

1. **Ativar ambiente virtual** (se criou um):
   ```bash
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

2. **Executar migrações** (se necessário):
   ```bash
   python manage.py migrate
   ```

3. **Iniciar servidor de desenvolvimento**:
   ```bash
   python manage.py runserver 0.0.0.0:8000
   ```

4. **Acessar a API**:
   - A API estará disponível em: `http://localhost:8000`
   - Documentação dos endpoints: Veja seção [Endpoints da API](#endpoints-da-api)

### Modo Produção com Gunicorn

```bash
gunicorn ad_api.wsgi:application --bind 0.0.0.0:8000 --workers 4
```

### Modo CLI (Alternativo)

Para uso via linha de comando (sem API):

```bash
python ad_password_change.py
```

A aplicação irá solicitar:
1. **Modo de operação**: Próprio usuário ou administrador
2. **Nome de usuário**: sAMAccountName ou UPN
3. **Senhas**: Conforme o modo escolhido

## Endpoints da API

### Base URL

```
http://localhost:8000/api
```

### 1. Verificar se Usuário Existe

**Endpoint:** `POST /api/user/exists`

**Body:**
```json
{
  "username": "usuario.teste"
}
```

**Body com credenciais customizadas (opcional):**
```json
{
  "username": "usuario.teste",
  "admin_user": "admin.ad",
  "admin_password": "senha-admin"
}
```

**Resposta de Sucesso (200):**
```json
{
  "exists": true,
  "dn": "CN=Usuario Teste,OU=Users,DC=hbh,DC=local"
}
```

**Resposta quando não existe (200):**
```json
{
  "exists": false,
  "dn": null
}
```

**Exemplo com cURL:**
```bash
curl -X POST http://localhost:8000/api/user/exists \
  -H "Content-Type: application/json" \
  -d '{"username": "usuario.teste"}'
```

---

### 2. Reset de Senha

**Endpoint:** `POST /api/password/reset`

**Body mínimo:**
```json
{
  "username": "usuario.teste",
  "new_password": "NovaSenha123!"
}
```

**Body completo:**
```json
{
  "username": "usuario.teste",
  "new_password": "NovaSenha123!",
  "force_change_next_logon": true,
  "admin_user": "admin.ad",
  "admin_password": "senha-admin"
}
```

**Parâmetros:**
- `username` (obrigatório): Nome do usuário (sAMAccountName ou UPN)
- `new_password` (obrigatório): Nova senha
- `force_change_next_logon` (opcional, padrão: `true`): Força alteração no próximo logon
- `admin_user` (opcional): Usuário admin (usa do .env se não fornecido)
- `admin_password` (opcional): Senha admin (usa do .env se não fornecido)

**Resposta de Sucesso (200):**
```json
{
  "success": true
}
```

**Resposta de Erro (400):**
```json
{
  "success": false,
  "detail": "Mensagem de erro descritiva"
}
```

**Exemplo com cURL:**
```bash
curl -X POST http://localhost:8000/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "username": "usuario.teste",
    "new_password": "NovaSenha123!",
    "force_change_next_logon": true
  }'
```

**Exemplo com Python (requests):**
```python
import requests

url = "http://localhost:8000/api/password/reset"
data = {
    "username": "usuario.teste",
    "new_password": "NovaSenha123!",
    "force_change_next_logon": True
}

response = requests.post(url, json=data)
print(response.json())
```

## Docker

### Passo 1: Criar .env

```bash
cp ENV_TEMPLATE .env
```

Edite o `.env` com suas configurações (veja seção [Configuração](#configuração)).

### Passo 2: Construir e Executar

```bash
docker compose up --build -d
```

### Passo 3: Verificar Logs

```bash
docker compose logs -f
```

### Passo 4: Parar

```bash
docker compose down
```

### Acessar API

- `http://localhost:8000/api/user/exists`
- `http://localhost:8000/api/password/reset`

## Checklist Antes de Usar

- [ ] Python 3.8+ instalado
- [ ] Dependências instaladas (`pip install -r requirements.txt`)
- [ ] Arquivo `.env` criado e configurado
- [ ] LDAPS configurado no servidor AD (ou LDAP funciona)
- [ ] Conectividade de rede testada (portas 389/636)
- [ ] Credenciais de admin configuradas no `.env`
- [ ] Base DN configurada corretamente
- [ ] Servidor Django rodando ou Docker iniciado
- [ ] API testada com um usuário de teste

## Segurança

### Boas Práticas

1. **Nunca commite o arquivo `.env`**
   - O arquivo está no `.gitignore` por padrão
   - Verifique antes de fazer commit

2. **Use LDAPS em produção**
   - Configure certificado válido no servidor AD
   - Use `SSL_VERIFY=true` em produção

3. **Proteja as credenciais de admin**
   - Use um usuário com permissões mínimas necessárias
   - Rotacione senhas regularmente

4. **Configure ALLOWED_HOSTS**
   - Em produção, defina hosts específicos:
     ```
     ALLOWED_HOSTS=api.empresa.com,192.168.1.100
     ```

5. **Use HTTPS em produção**
   - Configure um proxy reverso (nginx, Apache) com SSL
   - Não exponha a API diretamente na internet

6. **Políticas de Senha**
   - Configure políticas adequadas no AD
   - Valide complexidade de senhas no frontend

### Variáveis de Ambiente Sensíveis

⚠️ **NUNCA** exponha ou commite:
- `AD_ADMIN_PASSWORD`
- `SECRET_KEY`
- Qualquer senha ou token

## Solução de Problemas

### Erros Comuns

#### 1. Erro de Conexão

**Mensagem:**
```
Erro ao conectar ao AD: [Errno 10054] ...
```

**Soluções:**
- Verifique se o servidor AD está acessível
- Teste conectividade: `Test-NetConnection -ComputerName IP -Port 389`
- Verifique firewall (portas 389/636 devem estar abertas)
- Confirme IP/hostname correto no `.env`

#### 2. Erro SSL/TLS

**Mensagem:**
```
Erro SSL/TLS: certificate verify failed
```

**Soluções:**
- Configure `SSL_VERIFY=false` no `.env` (apenas para testes)
- Para produção: Configure certificado válido no servidor AD
- Certifique-se de que o servidor AD tem certificado LDAPS instalado

#### 3. Usuário Não Encontrado

**Mensagem:**
```
{'exists': false, 'dn': null}
```

**Soluções:**
- Verifique se o nome de usuário está correto
- Confirme que `AD_BASE_DN` está correto
- Usuário pode estar em OU diferente (a busca já verifica várias OUs)

#### 4. Falha na Autenticação de Admin

**Mensagem:**
```
{'detail': 'Falha ao autenticar admin no AD'}
```

**Soluções:**
- Verifique usuário e senha no `.env`
- Confirme que o usuário tem permissões de reset de senha
- Teste login manual no AD com essas credenciais

#### 5. Política de Senha

**Mensagem:**
```
Falha na alteração da senha: passwordTooShort
```

**Soluções:**
- A senha deve atender políticas do AD:
  - Comprimento mínimo (geralmente 8+ caracteres)
  - Complexidade (maiúsculas, minúsculas, números, símbolos)
  - Não pode ser recentemente usada
  - Não pode conter nome de usuário
- Verifique políticas no AD: `Get-ADDefaultDomainPasswordPolicy`

#### 6. Erro "UnwillingToPerform"

**Mensagem:**
```
Falha na alteração da senha: O servidor não pode executar a operação
```

**Soluções:**
- **Mais comum**: Use LDAPS (conexão segura)
  - Configure `AD_SERVER=ldaps://IP:636`
  - Execute script PowerShell no servidor AD
- Verifique permissões do admin
- Alguns ADs exigem conexão segura para reset de senha

#### 7. Django não inicia

**Mensagem:**
```
django.core.exceptions.ImproperlyConfigured: ...
```

**Soluções:**
- Verifique se o arquivo `.env` existe
- Confirme que todas as variáveis obrigatórias estão definidas
- Execute: `python manage.py check`

### Debug

Para ver logs detalhados:

```bash
# Django em modo debug
python manage.py runserver --verbosity 2

# Docker logs
docker compose logs -f

# Verificar configuração Django
python manage.py check --deploy
```

### Testes de Conectividade

```bash
# Testar LDAP
python -c "from ldap3 import Server, Connection; s = Server('192.168.100.23', port=389); print('LDAP OK' if s else 'LDAP FALHOU')"

# Testar LDAPS
python -c "from ldap3 import Server; s = Server('192.168.100.23', port=636, use_ssl=True); print('LDAPS OK' if s else 'LDAPS FALHOU')"
```

## Exemplos Práticos

### Exemplo 1: Reset de Senha Básico

```bash
curl -X POST http://localhost:8000/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "username": "joao.silva",
    "new_password": "NovaSenha123!@#"
  }'
```

### Exemplo 2: Verificar se Usuário Existe

```bash
curl -X POST http://localhost:8000/api/user/exists \
  -H "Content-Type: application/json" \
  -d '{"username": "joao.silva"}'
```

### Exemplo 3: Reset sem Forçar Alteração no Próximo Logon

```json
{
  "username": "maria.santos",
  "new_password": "Senha123!@#",
  "force_change_next_logon": false
}
```

### Exemplo 4: Usando Python requests

```python
import requests

BASE_URL = "http://localhost:8000/api"

# Verificar se usuário existe
response = requests.post(
    f"{BASE_URL}/user/exists",
    json={"username": "usuario.teste"}
)
print(response.json())

# Reset de senha
response = requests.post(
    f"{BASE_URL}/password/reset",
    json={
        "username": "usuario.teste",
        "new_password": "NovaSenha123!",
        "force_change_next_logon": True
    }
)
print(response.json())
```

## Estrutura do Projeto

```
ad_password_change/
├── ad_password_change.py      # Módulo principal (CLI)
├── config.py                 # Configurações do AD
├── requirements.txt          # Dependências Python
├── manage.py                # Django management
├── ENV_TEMPLATE             # Template para .env
├── EXECUTAR_ESTE_NO_SERVIDOR_AD.ps1  # Script para configurar LDAPS no servidor AD
├── ad_api/                  # Configuração Django
│   ├── settings.py
│   └── urls.py
├── accounts/                # App Django (API)
│   ├── views.py            # Endpoints da API
│   └── urls.py
├── Dockerfile              # Configuração Docker
├── docker-compose.yml      # Docker Compose
└── README.md               # Este arquivo
```

## Estrutura do Projeto

```
ad_password_change/
├── ad_password_change.py      # Módulo principal (CLI)
├── config.py                  # Configurações do AD (modo CLI)
├── manage.py                  # Django management
├── requirements.txt            # Dependências Python
├── .env                       # Variáveis de ambiente (criar a partir do template)
├── ENV_TEMPLATE               # Template para .env
├── Dockerfile                 # Configuração Docker
├── docker-compose.yml         # Docker Compose
├── entrypoint.sh              # Script de inicialização Docker
├── EXECUTAR_ESTE_NO_SERVIDOR_AD.ps1  # Script para configurar LDAPS
├── ad_api/                    # Configuração Django
│   ├── __init__.py
│   ├── settings.py           # Configurações Django
│   ├── urls.py                # URLs principais
│   ├── wsgi.py                # WSGI para produção
│   └── asgi.py                # ASGI (se necessário)
├── accounts/                  # App Django (API)
│   ├── __init__.py
│   ├── apps.py
│   ├── urls.py                # URLs da API
│   └── views.py               # Endpoints da API
└── README.md                  # Este arquivo
```

## Desenvolvimento

### Contribuindo

1. Faça fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

### Estrutura do Código

- **`accounts/views.py`**: Contém os endpoints da API
- **`ad_password_change.py`**: Contém a lógica principal de alteração de senha
- **`ad_api/settings.py`**: Configurações do Django

## Suporte

Para problemas, dúvidas ou sugestões:
- Abra uma [Issue no GitHub](https://github.com/FernandoL9/ad_password_change/issues)
- Verifique a seção [Solução de Problemas](#solução-de-problemas)

## Licença

Este projeto é fornecido como exemplo educacional. Use com responsabilidade e de acordo com as políticas de segurança da sua organização.

---

**Desenvolvido com ❤️ para facilitar a gestão de senhas no Active Directory**
