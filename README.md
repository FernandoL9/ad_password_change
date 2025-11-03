# Alteração de Senha no Active Directory via LDAPS

Esta aplicação Python permite que usuários alterem suas próprias senhas no Active Directory de forma segura através de conexão LDAPS (LDAP sobre SSL/TLS).

## Características

- ✅ Conexão segura via LDAPS (porta 636)
- ✅ Autenticação do próprio usuário (Self-Service Password Change)
- ✅ Tratamento robusto de erros
- ✅ Interface console amigável
- ✅ Configuração flexível via arquivo de configuração
- ✅ Validação de entrada de dados

## Requisitos

- Python 3.6 ou superior
- Biblioteca `ldap3`
- Acesso ao servidor Active Directory via LDAPS
- Credenciais válidas do usuário

## Instalação

1. Clone ou baixe este repositório
2. Instale as dependências:

```bash
pip install -r requirements.txt
```

## Configuração

1. Edite o arquivo `config.py` com as informações do seu ambiente:

```python
# Servidor do Active Directory
AD_SERVER = 'ldaps://seu-controlador-de-dominio.com:636'

# Base DN para busca de usuários
AD_BASE_DN = 'DC=empresa,DC=local'

# Timeout para conexão LDAP (em segundos)
LDAP_TIMEOUT = 30

# Configurações de SSL/TLS
SSL_VERIFY = True  # Defina como False apenas para ambientes de teste
```

### Configurações Importantes

- **AD_SERVER**: Use `ldaps://` para conexão segura ou `ldap://` para fallback automático
- **AD_BASE_DN**: Substitua pelos valores do seu domínio (ex: `DC=empresa,DC=local`)
- **SSL_VERIFY**: Use `False` para certificados autoassinados, `True` para certificados confiáveis

### Configurar LDAPS no Servidor AD

Para habilitar LDAPS no servidor Active Directory, execute o script PowerShell no servidor AD:

1. Copie `EXECUTAR_ESTE_NO_SERVIDOR_AD.ps1` para o servidor AD
2. Execute como Administrador (botão direito → Executar como Administrador)
3. Aguarde a conclusão (2-5 minutos)
4. Aguarde mais 10 minutos para ativação completa
5. Atualize `config.py` com `AD_SERVER = 'ldaps://192.168.100.23:636'`

## Uso

Console (modo CLI):

```bash
python ad_password_change.py
```

A aplicação irá solicitar:

1. **Nome de usuário**: sAMAccountName ou UPN (ex: `joao.silva` ou `joao.silva@empresa.com`)
2. **Senha atual**: Sua senha atual do Active Directory
3. **Nova senha**: A senha que deseja definir
4. **Confirmação**: Confirmação da nova senha

### Exemplo de Uso

```
=== Alteração de Senha no Active Directory ===

Digite seu nome de usuário (sAMAccountName ou UPN): joao.silva
Digite sua senha atual: [oculta]
Digite sua nova senha: [oculta]
Confirme sua nova senha: [oculta]

Tentando alterar a senha para o usuário: joao.silva
Conectando ao Active Directory...
✅ Senha alterada com sucesso!
```

## API REST (Django + DRF)

### Instalação

```bash
pip install -r requirements.txt
```

Crie o arquivo `.env` a partir do template:

```bash
cp ENV_TEMPLATE .env
```

Edite `.env` com seus dados (AD_SERVER, AD_BASE_DN, AD_ADMIN_USER, AD_ADMIN_PASSWORD, etc.).

### Executar o servidor

```bash
python manage.py runserver 0.0.0.0:8000
```

### Docker

1. Criar `.env` a partir do template e ajustar as variáveis

```bash
cp ENV_TEMPLATE .env
```

2. Subir com Docker Compose

```bash
docker compose up --build -d
```

3. Acessar

```
http://localhost:8000/api/user/exists
http://localhost:8000/api/password/reset
```

### Endpoints

- POST `/api/user/exists`

  - Body JSON: `{ "username": "usuario.teste" }`
  - Resposta: `{ "exists": true, "dn": "CN=Usuario Teste,OU=...,DC=..." }`

- POST `/api/password/reset`
  - Body JSON: `{ "username": "usuario.teste", "new_password": "NovaSenha123!" }`
  - Opcional: `admin_user`, `admin_password`, `force_change_next_logon` (boolean)
  - Resposta: `{ "success": true }` ou `{ "success": false, "detail": "mensagem" }`

As credenciais de admin são lidas do `.env` por padrão (recomendado). Você pode sobrepor enviando no body do request.

## Tratamento de Erros

A aplicação trata os seguintes tipos de erro:

- **Falha na conexão LDAPS**: Problemas de conectividade ou SSL
- **Falha na autenticação**: Senha incorreta ou conta bloqueada
- **Usuário não encontrado**: Nome de usuário inválido
- **Políticas de senha**: Senha não atende aos requisitos do AD
- **Erros de rede**: Timeouts e problemas de conectividade

## Segurança

- ✅ Conexão sempre via LDAPS (SSL/TLS)
- ✅ Senhas não são exibidas no console
- ✅ Não há credenciais hardcoded no código
- ✅ Validação de entrada de dados
- ✅ Tratamento seguro de exceções

## Solução de Problemas

### Erro de Conexão SSL

```
Erro SSL/TLS: certificate verify failed
```

**Solução**: Verifique se o certificado SSL do servidor AD é válido ou configure `SSL_VERIFY = False` apenas para testes.

### Usuário Não Encontrado

```
Usuário 'username' não encontrado no Active Directory
```

**Solução**: Verifique se o nome de usuário está correto e se o `AD_BASE_DN` está configurado corretamente.

### Falha na Autenticação

```
Erro de autenticação: invalidCredentials
```

**Solução**: Verifique se a senha atual está correta e se a conta não está bloqueada.

### Política de Senha

```
Falha na alteração da senha: passwordTooShort
```

**Solução**: A nova senha deve atender às políticas de senha do Active Directory (comprimento mínimo, complexidade, etc.).

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

## Desenvolvimento

### Função Principal

A função `alterar_senha_ad()` é o núcleo da aplicação:

```python
def alterar_senha_ad(username, senha_antiga, nova_senha, ad_server=None, ad_base_dn=None):
    """
    Altera a senha de um usuário no Active Directory via LDAPS

    Args:
        username (str): Nome de usuário (sAMAccountName ou UPN)
        senha_antiga (str): Senha atual do usuário
        nova_senha (str): Nova senha desejada
        ad_server (str): Servidor AD (opcional)
        ad_base_dn (str): Base DN do AD (opcional)

    Returns:
        bool: True se a alteração foi bem-sucedida

    Raises:
        ADPasswordChangeError: Em caso de erro na alteração da senha
    """
```

### Personalização

Você pode personalizar a aplicação modificando:

- **config.py**: Configurações do servidor AD
- **ad_password_change.py**: Lógica de negócio e tratamento de erros
- **Interface**: Modificar a função `obter_entrada_usuario()` para diferentes tipos de entrada

## Licença

Este projeto é fornecido como exemplo educacional. Use com responsabilidade e de acordo com as políticas de segurança da sua organização.
