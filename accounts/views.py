from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM
from ad_password_change import alterar_senha_ad, ADPasswordChangeError, _preparar_metodos_autenticacao


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
            return Response({'detail': 'username é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        # Permitir sobrepor credenciais de admin pelo corpo da requisição
        admin_user = (request.data.get('admin_user') or settings.AD_ADMIN_USER)
        admin_password = (request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD)
        if not admin_user or not admin_password:
            return Response({'detail': 'Credenciais de admin não configuradas'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Usar a nova função que suporta LDAPS com fallback
            server = _criar_servidor_ldap_com_fallback(settings.AD_SERVER)
            conn = _try_bind_methods(server, admin_user, admin_password, settings.AD_BASE_DN)
            if not conn:
                return Response({'detail': 'Falha ao autenticar admin no AD'}, status=status.HTTP_502_BAD_GATEWAY)
        except Exception as e:
            return Response({'detail': f'Erro ao conectar ao AD: {str(e)}'}, status=status.HTTP_502_BAD_GATEWAY)

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

        return Response({'exists': bool(found_dn), 'dn': found_dn}, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    def post(self, request):
        username = request.data.get('username', '').strip()
        new_password = request.data.get('new_password', '')
        admin_user = request.data.get('admin_user') or settings.AD_ADMIN_USER
        admin_password = request.data.get('admin_password') or settings.AD_ADMIN_PASSWORD
        force_change_next_logon = bool(request.data.get('force_change_next_logon', True))

        if not username or not new_password:
            return Response({'detail': 'username e new_password são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)
        if not admin_user or not admin_password:
            return Response({'detail': 'Credenciais de admin não configuradas'}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({'success': False, 'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'success': False, 'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


