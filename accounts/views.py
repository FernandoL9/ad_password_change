from django.conf import settings
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM
from ad_password_change import alterar_senha_ad, ADPasswordChangeError, _preparar_metodos_autenticacao
import pyotp
import hashlib
import time
import base64


def _criar_servidor_ldap_com_fallback(ad_server):
    """
    Cria um servidor LDAP com suporte a LDAPS e fallback automático.
    Usa a mesma lógica corrigida de alterar_senha_ad.
    """
    # Extrair hostname/IP da URL
    server_url = ad_server
    if server_url.startswith('ldap://'):
        server_url = server_url[7:]  # Remove 'ldap://'
    elif server_url.startswith('ldaps://'):
        server_url = server_url[8:]  # Remove 'ldaps://'
    
    # Separar hostname e porta se presente
    if ':' in server_url:
        hostname, port_str = server_url.rsplit(':', 1)
        port = int(port_str)
    else:
        hostname = server_url
        port = None
    
    # Detectar se deve tentar SSL primeiro
    prefer_ssl = ad_server.startswith('ldaps://') or (port and port == 636)
    
    # Tentar LDAPS primeiro se configurado, depois LDAP como fallback
    connection_attempts = []
    if prefer_ssl:
        connection_attempts.append((True, 636, "LDAPS"))
    connection_attempts.append((False, 389, "LDAP"))
    
    for ssl_enabled, conn_port, conn_type in connection_attempts:
        try:
            server = Server(
                f"{hostname}:{conn_port}",
                use_ssl=ssl_enabled,
                get_info=ALL,
                connect_timeout=settings.LDAP_TIMEOUT
            )
            return server
        except Exception:
            if not ssl_enabled:  # Se é o último (LDAP), levantar erro
                raise
            continue
    
    # Se chegou aqui, falhou tudo
    raise Exception("Não foi possível configurar conexão com o servidor AD")


def _try_bind_methods(server, username, password, base_dn):
    """Reutiliza a mesma estratégia de autenticação da aplicação CLI"""
    methods = _preparar_metodos_autenticacao(username, base_dn)
    for user_fmt, auth_type in methods:
        try:
            conn = Connection(
                server,
                user=user_fmt,
                password=password,
                authentication=auth_type,
                auto_bind=True,
                receive_timeout=settings.LDAP_TIMEOUT,
            )
            if conn.bound:
                return conn
        except Exception:
            continue
    return None


class UserExistsView(APIView):
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({
                'success': False,
                'detail': 'username é obrigatório',
                'exists': False,
                'dn': None
            }, status=status.HTTP_200_OK)

        # Permitir sobrepor credenciais de admin pelo corpo da requisição
        admin_user = (request.data.get('admin_user') or settings.AD_ADMIN_USER)
        admin_password = (request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD)
        if not admin_user or not admin_password:
            return Response({
                'success': False,
                'detail': 'Credenciais de admin não configuradas',
                'exists': False,
                'dn': None
            }, status=status.HTTP_200_OK)

        try:
            # Usar a nova função que suporta LDAPS com fallback
            server = _criar_servidor_ldap_com_fallback(settings.AD_SERVER)
            conn = _try_bind_methods(server, admin_user, admin_password, settings.AD_BASE_DN)
            if not conn:
                return Response({
                    'success': False,
                    'detail': 'Falha ao autenticar admin no AD',
                    'exists': False,
                    'dn': None
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao conectar ao AD: {str(e)}',
                'exists': False,
                'dn': None
            }, status=status.HTTP_200_OK)

        search_filter = f"(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"
        bases = [
            settings.AD_BASE_DN,
            f"CN=Users,{settings.AD_BASE_DN}",
            f"OU=HOMOLOGACAO,{settings.AD_BASE_DN}",
            f"OU=HOSPITAL BELO HORIZONTE,{settings.AD_BASE_DN}",
            f"OU=PAINEIS,{settings.AD_BASE_DN}",
            f"OU=Restaurante,{settings.AD_BASE_DN}",
            f"OU=SERVIDORES,{settings.AD_BASE_DN}",
            f"OU=TECNOLOGIA DA INFORMACAO,{settings.AD_BASE_DN}",
            f"OU=teste,{settings.AD_BASE_DN}",
        ]
        found_dn = None
        try:
            for base in bases:
                conn.search(base, search_filter, attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName'])
                if conn.entries:
                    found_dn = str(conn.entries[0].distinguishedName)
                    break
        finally:
            conn.unbind()

        return Response({
            'success': True,
            'exists': bool(found_dn),
            'dn': found_dn
        }, status=status.HTTP_200_OK)


class UserInfoView(APIView):
    """
    Retorna todas as informações disponíveis de um usuário no Active Directory
    """
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({
                'success': False,
                'detail': 'username é obrigatório',
                'user': None
            }, status=status.HTTP_200_OK)

        # Permitir sobrepor credenciais de admin pelo corpo da requisição
        admin_user = (request.data.get('admin_user') or settings.AD_ADMIN_USER)
        admin_password = (request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD)
        if not admin_user or not admin_password:
            return Response({
                'success': False,
                'detail': 'Credenciais de admin não configuradas',
                'user': None
            }, status=status.HTTP_200_OK)

        try:
            # Usar a nova função que suporta LDAPS com fallback
            server = _criar_servidor_ldap_com_fallback(settings.AD_SERVER)
            conn = _try_bind_methods(server, admin_user, admin_password, settings.AD_BASE_DN)
            if not conn:
                return Response({
                    'success': False,
                    'detail': 'Falha ao autenticar admin no AD',
                    'user': None
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao conectar ao AD: {str(e)}',
                'user': None
            }, status=status.HTTP_200_OK)

        search_filter = f"(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"
        bases = [
            settings.AD_BASE_DN,
            f"CN=Users,{settings.AD_BASE_DN}",
            f"OU=HOMOLOGACAO,{settings.AD_BASE_DN}",
            f"OU=HOSPITAL BELO HORIZONTE,{settings.AD_BASE_DN}",
            f"OU=PAINEIS,{settings.AD_BASE_DN}",
            f"OU=Restaurante,{settings.AD_BASE_DN}",
            f"OU=SERVIDORES,{settings.AD_BASE_DN}",
            f"OU=TECNOLOGIA DA INFORMACAO,{settings.AD_BASE_DN}",
            f"OU=teste,{settings.AD_BASE_DN}",
        ]
        
        user_info = None
        try:
            # Buscar todos os atributos disponíveis (None retorna todos)
            for base in bases:
                conn.search(
                    base, 
                    search_filter, 
                    attributes=['*', '+']  # '*' busca todos os atributos, '+' busca atributos operacionais
                )
                if conn.entries:
                    entry = conn.entries[0]
                    # Converter a entrada LDAP em dicionário
                    user_info = {}
                    for attr in entry.entry_attributes:
                        try:
                            value = getattr(entry, attr, None)
                            if value is not None:
                                # Converter valores para tipos Python nativos
                                if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                                    user_info[attr] = [str(v) for v in value]
                                else:
                                    user_info[attr] = str(value)
                        except Exception:
                            # Ignorar atributos que não podem ser lidos
                            continue
                    break
        finally:
            conn.unbind()

        if not user_info:
            return Response({
                'success': False,
                'detail': 'Usuário não encontrado',
                'user': None
            }, status=status.HTTP_200_OK)

        return Response({
            'success': True,
            'user': user_info
        }, status=status.HTTP_200_OK)


class UserPhoneView(APIView):
    """
    Retorna os números de telefone de um usuário específico
    """
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({
                'success': False,
                'detail': 'username é obrigatório',
                'user': None
            }, status=status.HTTP_200_OK)

        # Permitir sobrepor credenciais de admin pelo corpo da requisição
        admin_user = (request.data.get('admin_user') or settings.AD_ADMIN_USER)
        admin_password = (request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD)
        if not admin_user or not admin_password:
            return Response({
                'success': False,
                'detail': 'Credenciais de admin não configuradas',
                'user': None
            }, status=status.HTTP_200_OK)

        try:
            # Usar a nova função que suporta LDAPS com fallback
            server = _criar_servidor_ldap_com_fallback(settings.AD_SERVER)
            conn = _try_bind_methods(server, admin_user, admin_password, settings.AD_BASE_DN)
            if not conn:
                return Response({
                    'success': False,
                    'detail': 'Falha ao autenticar admin no AD',
                    'user': None
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao conectar ao AD: {str(e)}',
                'user': None
            }, status=status.HTTP_200_OK)

        # Atributos de telefone no Active Directory
        phone_attributes = [
            'telephoneNumber',      # Telefone principal/comercial
            'mobile',               # Celular
            'homePhone',            # Telefone residencial
            'otherTelephone',       # Outros telefones (pode ser múltiplo)
            'ipPhone',              # Telefone IP
            'facsimileTelephoneNumber',  # Fax
        ]

        search_filter = f"(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"
        bases = [
            settings.AD_BASE_DN,
            f"CN=Users,{settings.AD_BASE_DN}",
            f"OU=HOMOLOGACAO,{settings.AD_BASE_DN}",
            f"OU=HOSPITAL BELO HORIZONTE,{settings.AD_BASE_DN}",
            f"OU=PAINEIS,{settings.AD_BASE_DN}",
            f"OU=Restaurante,{settings.AD_BASE_DN}",
            f"OU=SERVIDORES,{settings.AD_BASE_DN}",
            f"OU=TECNOLOGIA DA INFORMACAO,{settings.AD_BASE_DN}",
            f"OU=teste,{settings.AD_BASE_DN}",
        ]
        
        user_phones = {}
        user_found = False
        try:
            for base in bases:
                conn.search(
                    base, 
                    search_filter, 
                    attributes=phone_attributes + ['sAMAccountName', 'displayName', 'cn']
                )
                if conn.entries:
                    entry = conn.entries[0]
                    user_found = True
                    
                    # Informações básicas do usuário
                    user_phones['username'] = str(getattr(entry, 'sAMAccountName', username))
                    user_phones['displayName'] = str(getattr(entry, 'cn', getattr(entry, 'displayName', 'N/A')))
                    
                    # Buscar telefones
                    phones = {}
                    for attr in phone_attributes:
                        try:
                            value = getattr(entry, attr, None)
                            if value is not None:
                                if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                                    phones[attr] = [str(v) for v in value]
                                else:
                                    phones[attr] = str(value)
                        except Exception:
                            continue
                    
                    user_phones['phones'] = phones
                    break
        finally:
            conn.unbind()

        if not user_found:
            return Response({
                'success': False,
                'detail': 'Usuário não encontrado',
                'user': None
            }, status=status.HTTP_200_OK)

        return Response({
            'success': True,
            'user': user_phones
        }, status=status.HTTP_200_OK)


class ListUsersView(APIView):
    """
    Lista todos os usuários do Active Directory com suas informações básicas
    """
    def post(self, request):
        # Permitir sobrepor credenciais de admin pelo corpo da requisição
        admin_user = (request.data.get('admin_user') or settings.AD_ADMIN_USER)
        admin_password = (request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD)
        if not admin_user or not admin_password:
            return Response({
                'success': False,
                'detail': 'Credenciais de admin não configuradas',
                'count': 0,
                'users': []
            }, status=status.HTTP_200_OK)

        # Parâmetros opcionais
        try:
            limit = int(request.data.get('limit', 100))  # Limite padrão de 100 usuários
        except (ValueError, TypeError):
            limit = 100
        
        # Incluir telefones por padrão
        default_attributes = [
            'sAMAccountName', 'displayName', 'userPrincipalName', 'mail', 'cn',
            'telephoneNumber', 'mobile', 'homePhone', 'otherTelephone'
        ]
        attributes = request.data.get('attributes', default_attributes)
        
        # Se attributes for uma string, converter para lista
        if isinstance(attributes, str):
            attributes = [a.strip() for a in attributes.split(',')]

        try:
            # Usar a nova função que suporta LDAPS com fallback
            server = _criar_servidor_ldap_com_fallback(settings.AD_SERVER)
            conn = _try_bind_methods(server, admin_user, admin_password, settings.AD_BASE_DN)
            if not conn:
                return Response({
                    'success': False,
                    'detail': 'Falha ao autenticar admin no AD',
                    'count': 0,
                    'users': []
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao conectar ao AD: {str(e)}',
                'count': 0,
                'users': []
            }, status=status.HTTP_200_OK)

        search_filter = "(&(objectClass=user)(objectCategory=person))"
        bases = [
            settings.AD_BASE_DN,
            f"CN=Users,{settings.AD_BASE_DN}",
            f"OU=HOMOLOGACAO,{settings.AD_BASE_DN}",
            f"OU=HOSPITAL BELO HORIZONTE,{settings.AD_BASE_DN}",
            f"OU=PAINEIS,{settings.AD_BASE_DN}",
            f"OU=Restaurante,{settings.AD_BASE_DN}",
            f"OU=SERVIDORES,{settings.AD_BASE_DN}",
            f"OU=TECNOLOGIA DA INFORMACAO,{settings.AD_BASE_DN}",
            f"OU=teste,{settings.AD_BASE_DN}",
        ]
        
        users = []
        try:
            for base in bases:
                conn.search(
                    base,
                    search_filter,
                    attributes=attributes,
                    size_limit=limit
                )
                
                for entry in conn.entries:
                    user_data = {}
                    for attr in attributes:
                        try:
                            value = getattr(entry, attr, None)
                            if value is not None:
                                if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                                    user_data[attr] = [str(v) for v in value]
                                else:
                                    user_data[attr] = str(value)
                        except Exception:
                            continue
                    if user_data:  # Só adicionar se tiver dados
                        users.append(user_data)
                
                if len(users) >= limit:
                    break
        finally:
            conn.unbind()

        return Response({
            'success': True,
            'count': len(users),
            'users': users[:limit]
        }, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    def post(self, request):
        username = request.data.get('username', '').strip()
        new_password = request.data.get('new_password', '')
        admin_user = request.data.get('admin_user') or settings.AD_ADMIN_USER
        admin_password = request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD
        force_change_next_logon = bool(request.data.get('force_change_next_logon', True))

        if not username or not new_password:
            return Response({
                'success': False,
                'detail': 'username e new_password são obrigatórios'
            }, status=status.HTTP_200_OK)
        if not admin_user or not admin_password:
            return Response({
                'success': False,
                'detail': 'Credenciais de admin não configuradas'
            }, status=status.HTTP_200_OK)

        try:
            ok = alterar_senha_ad(
                username=username,
                senha_antiga=None,
                nova_senha=new_password,
                ad_server=settings.AD_SERVER,
                ad_base_dn=settings.AD_BASE_DN,
                admin_user=admin_user,
                admin_password=admin_password,
                forcar_proximo_logon=force_change_next_logon,
            )
            return Response({'success': bool(ok)}, status=status.HTTP_200_OK)
        except ADPasswordChangeError as e:
            return Response({
                'success': False,
                'detail': str(e)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': str(e)
            }, status=status.HTTP_200_OK)


class MFAGenerateCodeView(APIView):
    """
    Gera um código MFA baseado em tempo (TOTP) que muda a cada 5 minutos
    O código é gerado baseado no username e SECRET_KEY do Django
    """
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({
                'success': False,
                'detail': 'username é obrigatório',
                'code': None,
                'username': None,
                'valid_for_seconds': None,
                'expires_at': None
            }, status=status.HTTP_200_OK)

        try:
            # Criar uma chave secreta única para o usuário baseada no username e SECRET_KEY
            # Isso garante que cada usuário tenha seu próprio código
            # Converter o hash SHA256 para Base32 (formato requerido pelo pyotp)
            hash_bytes = hashlib.sha256(
                f"{settings.SECRET_KEY}:{username}".encode()
            ).digest()
            user_secret = base64.b32encode(hash_bytes).decode('utf-8')

            # Criar TOTP com intervalo de 5 minutos (300 segundos)
            totp = pyotp.TOTP(user_secret, interval=getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300))
            
            # Gerar código atual
            current_code = totp.now()
            
            # Calcular tempo restante até o próximo código
            current_time = int(time.time())
            interval = getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300)
            time_remaining = interval - (current_time % interval)
            
            # Armazenar código no cache com chave única para evitar reuso
            cache_key = f"mfa_code_{username}_{current_time // interval}"
            cache.set(cache_key, current_code, timeout=interval + 10)  # +10 segundos de margem

            return Response({
                'success': True,
                'code': current_code,
                'username': username,
                'valid_for_seconds': time_remaining,
                'expires_at': current_time + time_remaining,
                'message': f'Código válido por {time_remaining} segundos'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao gerar código MFA: {str(e)}',
                'code': None,
                'username': username,
                'valid_for_seconds': None,
                'expires_at': None
            }, status=status.HTTP_200_OK)


class MFAVerifyCodeView(APIView):
    """
    Verifica se o código MFA fornecido é válido
    Aceita o código atual ou o código do período anterior (para tolerância de clock skew)
    """
    def post(self, request):
        username = request.data.get('username', '').strip()
        code = request.data.get('code', '').strip()
        
        if not username:
            return Response({
                'success': False,
                'valid': False,
                'detail': 'username é obrigatório'
            }, status=status.HTTP_200_OK)
        if not code:
            return Response({
                'success': False,
                'valid': False,
                'detail': 'code é obrigatório'
            }, status=status.HTTP_200_OK)

        try:
            # Criar a mesma chave secreta usada na geração
            # Converter o hash SHA256 para Base32 (formato requerido pelo pyotp)
            hash_bytes = hashlib.sha256(
                f"{settings.SECRET_KEY}:{username}".encode()
            ).digest()
            user_secret = base64.b32encode(hash_bytes).decode('utf-8')

            # Criar TOTP com intervalo de 5 minutos
            totp = pyotp.TOTP(user_secret, interval=getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300))
            
            # Verificar código atual e do período anterior (tolerância de clock skew)
            current_time = int(time.time())
            interval = getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300)
            
            # Verificar código atual
            is_valid = totp.verify(code, for_time=current_time)
            
            # Se não for válido, tentar com período anterior (para tolerância)
            if not is_valid:
                previous_time = current_time - interval
                is_valid = totp.verify(code, for_time=previous_time)
            
            # Verificar também no cache para evitar reuso
            cache_key_current = f"mfa_code_{username}_{current_time // interval}"
            cache_key_previous = f"mfa_code_{username}_{(current_time - interval) // interval}"
            
            cached_code_current = cache.get(cache_key_current)
            cached_code_previous = cache.get(cache_key_previous)
            
            # Verificar se o código já foi usado
            code_used_key = f"mfa_used_{username}_{code}"
            code_used = cache.get(code_used_key)
            
            if code_used:
                return Response({
                    'success': False,
                    'valid': False,
                    'detail': 'Código já foi utilizado'
                }, status=status.HTTP_200_OK)

            if is_valid:
                # Marcar código como usado (válido por 10 minutos para evitar reuso)
                cache.set(code_used_key, True, timeout=600)
                
                return Response({
                    'success': True,
                    'valid': True,
                    'message': 'Código MFA válido'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'valid': False,
                    'detail': 'Código MFA inválido ou expirado'
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'valid': False,
                'detail': f'Erro ao verificar código MFA: {str(e)}'
            }, status=status.HTTP_200_OK)


class MFAGetCurrentCodeView(APIView):
    """
    Retorna o código MFA atual sem gerar um novo
    Útil para verificar qual código está ativo no momento
    """
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({
                'success': False,
                'detail': 'username é obrigatório',
                'code': None,
                'username': None,
                'valid_for_seconds': None,
                'expires_at': None
            }, status=status.HTTP_200_OK)

        try:
            # Criar a mesma chave secreta
            # Converter o hash SHA256 para Base32 (formato requerido pelo pyotp)
            hash_bytes = hashlib.sha256(
                f"{settings.SECRET_KEY}:{username}".encode()
            ).digest()
            user_secret = base64.b32encode(hash_bytes).decode('utf-8')

            # Criar TOTP
            totp = pyotp.TOTP(user_secret, interval=getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300))
            
            # Obter código atual
            current_code = totp.now()
            
            # Calcular tempo restante
            current_time = int(time.time())
            interval = getattr(settings, 'MFA_CODE_VALIDITY_SECONDS', 300)
            time_remaining = interval - (current_time % interval)
            
            return Response({
                'success': True,
                'code': current_code,
                'username': username,
                'valid_for_seconds': time_remaining,
                'expires_at': current_time + time_remaining
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Erro ao obter código MFA: {str(e)}',
                'code': None,
                'username': username,
                'valid_for_seconds': None,
                'expires_at': None
            }, status=status.HTTP_200_OK)

