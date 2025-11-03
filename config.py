# Configurações do Active Directory
# Substitua pelos valores do seu ambiente

# Servidor do Active Directory
# Use ldap:// para conexão simples ou ldaps:// para conexão segura
# IMPORTANTE: Após configurar LDAPS no servidor AD, altere para ldaps://
# AD_SERVER = 'ldap://192.168.100.23:389'  # Altere para 'ldaps://192.168.100.23:636' após configurar LDAPS
AD_SERVER = 'ldaps://192.168.100.23:636'  # Altere para 'ldaps://192.168.100.23:636' após configurar LDAPS


# Base DN para busca de usuários (exemplo: DC=empresa,DC=local)
AD_BASE_DN = 'DC=hbh,DC=local'

# Timeout para conexão LDAP (em segundos)
LDAP_TIMEOUT = 30

# Configurações de SSL/TLS
SSL_VERIFY = False  # False para certificado autoassinado. Use True em produção com certificado confiável
