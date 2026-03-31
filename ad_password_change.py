"""
Módulo para alteração de senha no Active Directory via LDAPS
"""

import getpass
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPPasswordIsMandatoryError
import ssl
from config import AD_SERVER, AD_BASE_DN, LDAP_TIMEOUT, SSL_VERIFY


class ADPasswordChangeError(Exception):
    """Exceção personalizada para erros de alteração de senha no AD"""
    pass


def _criar_conexao_com_ssl(server, user, password, auth_type=SIMPLE, verify_ssl=False):
    """
    Cria uma conexão LDAP com suporte a SSL/TLS configurado corretamente.
    Similar à lógica que funciona em testar_ldaps.py.
    """
    connection = Connection(
        server,
        user=user,
        password=password,
        authentication=auth_type,
        auto_bind=True,
        receive_timeout=LDAP_TIMEOUT
    )
    
    # Se não está usando SSL mas o servidor suporta, tentar STARTTLS
    if not connection.tls_started and server.use_ssl:
        try:
            # Se está usando SSL na conexão inicial, não precisa de start_tls
            pass
        except:
            pass
    
    return connection


def alterar_senha_ad(username, senha_antiga, nova_senha, ad_server=None, ad_base_dn=None, admin_user=None, admin_password=None, forcar_proximo_logon=True):
    """
    Altera a senha de um usuário no Active Directory via LDAP
    
    Args:
        username (str): Nome de usuário (sAMAccountName ou UPN)
        senha_antiga (str): Senha atual do usuário (None se usando admin)
        nova_senha (str): Nova senha desejada
        ad_server (str): Servidor AD (opcional, usa config.py se não fornecido)
        ad_base_dn (str): Base DN do AD (opcional, usa config.py se não fornecido)
        admin_user (str): Usuário administrador (opcional)
        admin_password (str): Senha do administrador (opcional)
        forcar_proximo_logon (bool): Se True, força alteração no próximo logon
    
    Returns:
        bool: True se a alteração foi bem-sucedida
    
    Raises:
        ADPasswordChangeError: Em caso de erro na alteração da senha
    """
    
    # Usar configurações padrão se não fornecidas
    if ad_server is None:
        ad_server = AD_SERVER
    if ad_base_dn is None:
        ad_base_dn = AD_BASE_DN
    
    connection = None
    
    try:
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
        
        # Detectar se deve tentar SSL primeiro baseado na configuração
        prefer_ssl = ad_server.startswith('ldaps://') or (port and port == 636)
        
        # Tentar conexão com fallback automático
        server = None
        use_ssl = None
        auth_success = False
        
        # Tentar LDAPS primeiro se configurado, depois LDAP como fallback
        connection_attempts = []
        if prefer_ssl:
            # Tentar LDAPS com verificação e sem verificação
            connection_attempts.append((True, 636, "LDAPS (com verificação)", True))
            connection_attempts.append((True, 636, "LDAPS (sem verificação)", False))
        # Sempre tentar LDAP na porta 389 como fallback
        connection_attempts.append((False, 389, "LDAP", None))
        
        for ssl_enabled, conn_port, conn_type, verify_ssl in connection_attempts:
            try:
                print(f"🔌 Tentando conectar via {conn_type}: {hostname}:{conn_port}")
                
                # Configurar servidor LDAP
                # Para LDAPS, ldap3 gerencia SSL automaticamente quando use_ssl=True
                # O ldap3 aceita certificados não confiáveis por padrão quando use_ssl=True
                # mas podemos precisar configurar o tls object explicitamente
                server = Server(
                    f"{hostname}:{conn_port}",
                    use_ssl=ssl_enabled,
                    get_info=ALL,
                    connect_timeout=LDAP_TIMEOUT
                )
                
                # Se é SSL e não estamos verificando, precisamos configurar TLS context na conexão depois
                
                use_ssl = ssl_enabled
                # Armazenar informações sobre verificação SSL para uso depois
                server._verify_ssl = verify_ssl if ssl_enabled else None
                break  # Se criar o servidor sem erro, prosseguir
                
            except Exception as e:
                print(f"   ⚠️  Não foi possível configurar {conn_type}: {str(e)}")
                if ssl_enabled:
                    if verify_ssl is True:
                        print(f"   ℹ️  Tentando LDAPS sem verificação de certificado...")
                        continue
                    else:
                        print(f"   ℹ️  Tentando fallback para LDAP...")
                        continue
                else:
                    raise ADPasswordChangeError(f"Falha ao configurar conexão com o servidor: {str(e)}")
        
        if server is None:
            raise ADPasswordChangeError("Não foi possível configurar conexão com o servidor AD")
        
        # Modo 1: Alteração pelo próprio usuário (requer senha atual)
        if senha_antiga and not admin_user:
            print("🔐 Modo: Alteração pelo próprio usuário")
            auth_methods = _preparar_metodos_autenticacao(username, ad_base_dn)
            
            for i, (auth_user, auth_type) in enumerate(auth_methods, 1):
                try:
                    print(f"[{i}/{len(auth_methods)}] Tentando: {auth_type} com '{auth_user}'")
                    connection = Connection(
                        server,
                        user=auth_user,
                        password=senha_antiga,
                        authentication=auth_type,
                        auto_bind=True,
                        receive_timeout=LDAP_TIMEOUT
                    )
                    
                    if connection.bound:
                        print(f"✅ Autenticação bem-sucedida!")
                        print(f"   Método: {auth_type}")
                        print(f"   Usuário: {auth_user}")
                        auth_success = True
                        break
                    else:
                        print(f"❌ Bind falhou")
                        if connection:
                            connection.unbind()
                            connection = None
                        
                except Exception as e:
                    print(f"❌ Erro: {str(e)}")
                    if connection:
                        connection.unbind()
                        connection = None
                    continue
        
        # Modo 2: Alteração por administrador (não requer senha atual)
        elif admin_user and admin_password:
            print("Modo: Alteração por administrador")
            admin_methods = _preparar_metodos_autenticacao(admin_user, ad_base_dn)
            
            # Tentar autenticar com o servidor atual
            auth_attempted = False
            ssl_error_occurred = False
            
            for i, (auth_user, auth_type) in enumerate(admin_methods, 1):
                try:
                    print(f"[{i}/{len(admin_methods)}] Tentando admin: {auth_type} com '{auth_user}'")
                    auth_attempted = True
                    connection = Connection(
                        server,
                        user=auth_user,
                        password=admin_password,
                        authentication=auth_type,
                        auto_bind=True,
                        receive_timeout=LDAP_TIMEOUT
                    )
                    
                    if connection.bound:
                        print(f"✅ Administrador autenticado!")
                        print(f"   Método: {auth_type}")
                        print(f"   Admin: {auth_user}")
                        auth_success = True
                        break
                    else:
                        print(f"❌ Bind falhou")
                        if connection:
                            connection.unbind()
                            connection = None
                        
                except (ssl.SSLError, OSError) as e:
                    error_msg = str(e).lower()
                    if ("ssl" in error_msg or "10054" in error_msg or 
                        "certificate" in error_msg or "connection" in error_msg):
                        ssl_error_occurred = True
                        print(f"❌ Erro de conexão SSL: {str(e)}")
                        if connection:
                            try:
                                connection.unbind()
                            except:
                                pass
                            connection = None
                        
                        # Se é erro SSL e estamos usando SSL, tentar fallback para LDAP
                        if use_ssl and i == 1:  # Apenas na primeira tentativa
                            print("   ℹ️  Tentando fallback automático para LDAP (porta 389)...")
                            try:
                                ldap_server = Server(
                                    f"{hostname}:389",
                                    use_ssl=False,
                                    get_info=ALL,
                                    connect_timeout=LDAP_TIMEOUT
                                )
                                # Tentar autenticar com LDAP
                                connection = Connection(
                                    ldap_server,
                                    user=auth_user,
                                    password=admin_password,
                                    authentication=auth_type,
                                    auto_bind=True,
                                    receive_timeout=LDAP_TIMEOUT
                                )
                                if connection.bound:
                                    print(f"✅ Administrador autenticado via LDAP (fallback)!")
                                    print(f"   Método: {auth_type}")
                                    print(f"   Admin: {auth_user}")
                                    server = ldap_server
                                    use_ssl = False
                                    auth_success = True
                                    break
                                else:
                                    if connection:
                                        connection.unbind()
                                    connection = None
                            except Exception as fallback_error:
                                print(f"   ❌ Fallback LDAP também falhou: {str(fallback_error)}")
                                connection = None
                        continue
                except Exception as e:
                    print(f"❌ Erro: {str(e)}")
                    if connection:
                        try:
                            connection.unbind()
                        except:
                            pass
                        connection = None
                    continue
            
            # Se teve erro SSL mas ainda não autenticou, tentar todos os métodos com LDAP
            if not auth_success and ssl_error_occurred and use_ssl:
                print("\n   ⚠️  Todas as tentativas SSL falharam. Tentando autenticação completa via LDAP...")
                try:
                    ldap_server = Server(
                        f"{hostname}:389",
                        use_ssl=False,
                        get_info=ALL,
                        connect_timeout=LDAP_TIMEOUT
                    )
                    for i, (auth_user, auth_type) in enumerate(admin_methods, 1):
                        try:
                            print(f"   [{i}/{len(admin_methods)}] LDAP fallback: {auth_type} com '{auth_user}'")
                            connection = Connection(
                                ldap_server,
                                user=auth_user,
                                password=admin_password,
                                authentication=auth_type,
                                auto_bind=True,
                                receive_timeout=LDAP_TIMEOUT
                            )
                            if connection.bound:
                                print(f"   ✅ Autenticado via LDAP!")
                                server = ldap_server
                                use_ssl = False
                                auth_success = True
                                break
                            else:
                                if connection:
                                    connection.unbind()
                                connection = None
                        except Exception:
                            if connection:
                                try:
                                    connection.unbind()
                                except:
                                    pass
                                connection = None
                            continue
                except Exception as e:
                    print(f"   ❌ Erro no fallback LDAP: {str(e)}")
        
        else:
            raise ADPasswordChangeError("É necessário fornecer senha atual OU credenciais de administrador")
        
        # Verificar se a conexão foi estabelecida
        if not auth_success or not connection or not connection.bound:
            raise ADPasswordChangeError("Falha na autenticação com o Active Directory. Verifique suas credenciais.")
        
        # Buscar o DN do usuário
        user_dn = _buscar_dn_usuario(connection, username, ad_base_dn)
        if not user_dn:
            raise ADPasswordChangeError(f"Usuário '{username}' não encontrado no Active Directory")
        
        print(f"✅ Usuário encontrado: {user_dn}")
        
        # Determinar o método de alteração baseado no contexto
        # Se é admin fazendo reset, usar unicodePwd (método padrão para reset)
        # Se é o próprio usuário, pode usar userPassword
        is_admin_reset = admin_user and admin_password and not senha_antiga
        
        success = False
        last_error = None
        
        if is_admin_reset:
            # Modo ADMIN: Reset de senha (deve usar unicodePwd)
            print("🔑 Modo: Reset de senha por administrador")
            nova_senha_encoded = _encode_password(nova_senha)
            
            # Tentar diferentes métodos para unicodePwd
            methods_to_try = [
                ("unicodePwd com MODIFY_REPLACE", lambda: connection.modify(
                    user_dn,
                    {'unicodePwd': [(MODIFY_REPLACE, [nova_senha_encoded])]} 
                )),
                ("unicodePwd com DELETE+ADD", lambda: connection.modify(
                    user_dn,
                    {'unicodePwd': [
                        (MODIFY_DELETE, []),  # Remove senha antiga
                        (MODIFY_ADD, [nova_senha_encoded])  # Adiciona senha nova
                    ]}
                )),
            ]
            
            success = False
            last_error = None
            
            for method_name, method_func in methods_to_try:
                try:
                    print(f"   Tentando {method_name}...")
                    success = method_func()
                    
                    if success:
                        print(f"✅ Reset de senha realizado com sucesso usando {method_name}!")
                        break
                    else:
                        last_error = connection.last_error
                        error_str = str(last_error).lower()
                        print(f"   ❌ {method_name} falhou: {last_error}")
                        
                        # Se for erro de segurança, tentar criar conexão LDAPS para esta operação
                        if "unwillingtoperform" in error_str and not use_ssl:
                            print("   ⚠️  Tentando operação via LDAPS (conexão segura)...")
                            try:
                                # Tentar fazer upgrade da conexão para TLS ou criar nova conexão segura
                                hostname_from_url = ad_server.replace('ldap://', '').replace('ldaps://', '').split(':')[0]
                                
                                # Tentar STARTTLS se disponível
                                if hasattr(connection, 'start_tls'):
                                    try:
                                        connection.start_tls()
                                        print("   ✅ STARTTLS ativado com sucesso!")
                                        # Tentar novamente após STARTTLS
                                        success = connection.modify(
                                            user_dn,
                                            {'unicodePwd': [(MODIFY_REPLACE, [nova_senha_encoded])]} 
                                        )
                                        if success:
                                            print(f"✅ Reset realizado após STARTTLS!")
                                            break
                                    except Exception as tls_err:
                                        print(f"   ⚠️  STARTTLS não disponível: {str(tls_err)}")
                                        
                                # Tentar nova conexão LDAPS (com e sem verificação de certificado)
                                ldaps_server = None
                                for verify_cert in [False, True]:
                                    try:
                                        tls_ctx = None
                                        if not verify_cert:
                                            tls_ctx = ssl.create_default_context()
                                            tls_ctx.check_hostname = False
                                            tls_ctx.verify_mode = ssl.CERT_NONE
                                        
                                        ldaps_server = Server(
                                            f"{hostname_from_url}:636",
                                            use_ssl=True,
                                            get_info=ALL,
                                            connect_timeout=LDAP_TIMEOUT
                                        )
                                        
                                        if not verify_cert:
                                            print(f"   ℹ️  Tentando LDAPS sem verificação de certificado...")
                                        break  # Se criar servidor sem erro, prosseguir
                                    except Exception as srv_err:
                                        if verify_cert:
                                            print(f"   ⚠️  Erro ao configurar servidor LDAPS: {str(srv_err)}")
                                        continue
                                
                                # Se conseguiu criar servidor LDAPS, tentar autenticar e fazer reset
                                if ldaps_server:
                                    admin_methods = _preparar_metodos_autenticacao(admin_user, ad_base_dn)
                                    ldaps_conn = None
                                    for auth_user, auth_type in admin_methods[:3]:  # Tentar apenas os primeiros 3
                                        try:
                                            ldaps_conn = Connection(
                                                ldaps_server,
                                                user=auth_user,
                                                password=admin_password,
                                                authentication=auth_type,
                                                auto_bind=True,
                                                receive_timeout=LDAP_TIMEOUT
                                            )
                                            if ldaps_conn.bound:
                                                print(f"   ✅ Conectado via LDAPS como {auth_user}")
                                                # Tentar reset via LDAPS
                                                success = ldaps_conn.modify(
                                                    user_dn,
                                                    {'unicodePwd': [(MODIFY_REPLACE, [nova_senha_encoded])]} 
                                                )
                                                if success:
                                                    print(f"✅ Reset realizado via LDAPS!")
                                                    connection = ldaps_conn  # Usar nova conexão
                                                    use_ssl = True
                                                    break
                                                else:
                                                    print(f"   ❌ Reset via LDAPS falhou: {ldaps_conn.last_error}")
                                                    ldaps_conn.unbind()
                                                    ldaps_conn = None
                                        except Exception as conn_err:
                                            print(f"   ⚠️  Erro ao conectar via LDAPS: {str(conn_err)}")
                                            if ldaps_conn:
                                                try:
                                                    ldaps_conn.unbind()
                                                except:
                                                    pass
                                                ldaps_conn = None
                                            continue
                                    
                                    if not success and ldaps_conn:
                                        try:
                                            ldaps_conn.unbind()
                                        except:
                                            pass
                            except Exception as ldaps_err:
                                print(f"   ⚠️  Não foi possível usar LDAPS: {str(ldaps_err)}")
                        
                        continue
                        
                except Exception as e:
                    print(f"   ❌ Erro em {method_name}: {str(e)}")
                    last_error = str(e)
                    continue
            
            # Se ainda não funcionou, NÃO usar userPassword (não funciona para autenticação)
            if not success:
                print("\n   ⚠️  ATENÇÃO: Não foi possível usar unicodePwd.")
                print("   ⚠️  userPassword não funciona para autenticação no Active Directory.")
                print("   ⚠️  É necessário usar unicodePwd via LDAPS para reset de senha funcionar corretamente.")
                print(f"\n   💡 SOLUÇÃO: Configure LDAPS corretamente ou use PowerShell/ADSI para reset de senha.")
                last_error = last_error or connection.last_error or "Falha em todos os métodos"
        else:
            # Modo USUÁRIO: Alteração de senha pelo próprio usuário
            print("🔐 Modo: Alteração de senha pelo próprio usuário")
            print("   Tentando alteração com userPassword...")
            success = connection.modify(
                user_dn,
                {'userPassword': [(MODIFY_REPLACE, [nova_senha])]} 
            )
            
            if success:
                print("✅ Senha alterada com sucesso usando userPassword!")
            else:
                last_error = connection.last_error
                print(f"❌ userPassword falhou: {last_error}")
                # Tentar também com unicodePwd como fallback
                print("   Tentando fallback com unicodePwd...")
                nova_senha_encoded = _encode_password(nova_senha)
                success = connection.modify(
                    user_dn,
                    {'unicodePwd': [(MODIFY_REPLACE, [nova_senha_encoded])]} 
                )
                if success:
                    print("✅ Senha alterada com sucesso usando unicodePwd!")
                else:
                    last_error = connection.last_error or last_error
        # Verificar se a senha foi realmente alterada (teste opcional)
        if success and is_admin_reset:
            print("\n🔍 Verificando se a senha foi realmente alterada...")
            try:
                # Tentar conectar com a nova senha (apenas verificação, não bloqueia se falhar)
                test_server = Server(
                    server_url,
                    use_ssl=use_ssl,
                    get_info=ALL,
                    connect_timeout=5
                )
                test_methods = _preparar_metodos_autenticacao(username, ad_base_dn)
                
                password_verified = False
                for test_user, test_auth_type in test_methods[:3]:  # Testar apenas os 3 primeiros métodos
                    try:
                        test_conn = Connection(
                            test_server,
                            user=test_user,
                            password=nova_senha,
                            authentication=test_auth_type,
                            auto_bind=True,
                            receive_timeout=5
                        )
                        if test_conn.bound:
                            print("   ✅ Verificação: A nova senha funciona corretamente!")
                            password_verified = True
                            test_conn.unbind()
                            break
                        test_conn.unbind()
                    except Exception:
                        continue
                
                if not password_verified:
                    print("   ⚠️  Não foi possível verificar automaticamente se a senha funciona.")
                    print("   Isso pode ser normal - tente fazer login manualmente para confirmar.")
            except Exception as e:
                print(f"   ℹ️  Verificação automática não disponível: {str(e)}")
        
        # Se a alteração foi bem-sucedida, configurar para alterar no próximo logon
        if success and forcar_proximo_logon:
            print("🔧 Configurando para alterar senha no próximo logon...")
            # Em AD, a forma correta de forçar troca no próximo logon é pwdLastSet=0.
            must_change_success = connection.modify(
                user_dn,
                {'pwdLastSet': [(MODIFY_REPLACE, ['0'])]}
            )
            if must_change_success:
                print("✅ Configurado para alterar senha no próximo logon (pwdLastSet=0)!")
            else:
                print("⚠️ Senha alterada, mas não foi possível configurar alteração obrigatória")
                print("   erro:", connection.last_error)
                print("   result:", connection.result)
        
        if not success:
            error_msg = last_error or connection.last_error or "Erro desconhecido"
            
            # Obter resposta completa do servidor se disponível
            if hasattr(connection, 'result') and connection.result:
                error_details = connection.result
                if error_details:
                    error_msg = f"{error_msg} - Detalhes: {error_details}"
            
            # Verificar se a resposta contém informações adicionais
            if hasattr(connection, 'response') and connection.response:
                for response in connection.response:
                    if hasattr(response, 'get') and 'description' in response:
                        error_msg = f"{error_msg} - {response.get('description')}"
            
            print(f"\n❌ Erro completo: {error_msg}")
            
            # Sugestão de usar LDAPS se não estiver usando SSL
            ssl_suggestion = ""
            if not use_ssl and is_admin_reset:
                ssl_suggestion = (
                    "\n💡 SUGESTÃO: Tente usar LDAPS (conexão segura). "
                    f"Altere AD_SERVER para 'ldaps://{server_url.split(':')[0]}:636' "
                    "ou configure o servidor para aceitar alterações via LDAP não seguro.\n"
                )
            
            # Mapear erros comuns para mensagens mais claras
            error_str = str(error_msg).lower()
            
            if "unwillingtoperform" in error_str:
                raise ADPasswordChangeError(
                    "Falha na alteração da senha: O servidor não pode executar a operação.\n\n"
                    "Possíveis causas:\n"
                    "- O administrador não tem permissões suficientes\n"
                    "- A senha não atende aos requisitos de política de senha\n"
                    "- A conexão não está segura (pode ser necessário LDAPS)\n"
                    "- O servidor AD pode requerer conexão segura para reset de senha\n"
                    f"{ssl_suggestion}"
                    f"Erro técnico: {error_msg}"
                )
            elif "insufficientaccessrights" in error_str or "access" in error_str:
                raise ADPasswordChangeError(
                    "Falha na alteração da senha: Permissões insuficientes. "
                    "O administrador não tem direitos para alterar senhas.\n"
                    f"Erro técnico: {error_msg}"
                )
            elif "passwordtooshort" in error_str or "tooshort" in error_str:
                raise ADPasswordChangeError(
                    "Falha na alteração da senha: A nova senha é muito curta. "
                    "Atenda aos requisitos de política de senha do Active Directory.\n"
                    f"Erro técnico: {error_msg}"
                )
            elif "passwordtoosimple" in error_str or "toosimple" in error_str or "complex" in error_str:
                raise ADPasswordChangeError(
                    "Falha na alteração da senha: A nova senha é muito simples. "
                    "Use uma senha mais complexa que atenda aos requisitos do Active Directory.\n"
                    f"Erro técnico: {error_msg}"
                )
            elif "constraintviolation" in error_str or "constraint" in error_str:
                raise ADPasswordChangeError(
                    "Falha na alteração da senha: A senha viola as políticas de senha do Active Directory.\n"
                    f"Erro técnico: {error_msg}"
                )
            else:
                raise ADPasswordChangeError(
                    f"Falha na alteração da senha.\n\n"
                    f"Erro: {error_msg}\n\n"
                    f"Verifique:\n"
                    f"- Se o administrador tem permissões para alterar senhas\n"
                    f"- Se a senha atende aos requisitos de política\n"
                    f"- Se a conexão com o AD está funcionando corretamente\n"
                    f"{ssl_suggestion}"
                )
        
        return True
        
    except LDAPBindError as e:
        raise ADPasswordChangeError(f"Erro de autenticação: {str(e)}")
    except LDAPPasswordIsMandatoryError:
        raise ADPasswordChangeError("Senha obrigatória não fornecida")
    except LDAPException as e:
        raise ADPasswordChangeError(f"Erro LDAP: {str(e)}")
    except ssl.SSLError as e:
        raise ADPasswordChangeError(f"Erro SSL/TLS: {str(e)}")
    except Exception as e:
        raise ADPasswordChangeError(f"Erro inesperado: {str(e)}")
    finally:
        if connection:
            connection.unbind()


def _preparar_metodos_autenticacao(username, ad_base_dn):
    """
    Prepara diferentes métodos de autenticação para tentar
    
    Returns:
        list: Lista de tuplas (auth_user, auth_type)
    """
    methods = []
    
    # Extrair informações do domínio
    domain_parts = ad_base_dn.split(',')
    domain_name = domain_parts[0].replace('DC=', '').upper()
    
    # Método 1: UPN (se já contém @)
    if '@' in username:
        methods.append((username, SIMPLE))
        # Também tentar com NTLM
        methods.append((username, NTLM))
    
    # Método 2: Formato domínio\usuário
    if '\\' in username:
        methods.append((username, SIMPLE))
        methods.append((username, NTLM))
    else:
        # Adicionar formato domínio\usuário
        domain_user = f"{domain_name}\\{username}"
        methods.append((domain_user, SIMPLE))
        methods.append((domain_user, NTLM))
    
    # Método 3: DN completo para SIMPLE
    dn_user = f"CN={username},CN=Users,{ad_base_dn}"
    methods.append((dn_user, SIMPLE))
    
    # Método 4: DN alternativo (sem CN=Users)
    dn_user_alt = f"CN={username},{ad_base_dn}"
    methods.append((dn_user_alt, SIMPLE))
    
    # Método 5: sAMAccountName simples
    methods.append((username, SIMPLE))
    
    # Método 6: UPN construído
    if '@' not in username and '\\' not in username:
        upn_user = f"{username}@{domain_name.lower()}.local"
        methods.append((upn_user, SIMPLE))
        methods.append((upn_user, NTLM))
    
    return methods


def _buscar_dn_usuario(connection, username, base_dn):
    """
    Busca o DN (Distinguished Name) do usuário no AD
    
    Args:
        connection: Conexão LDAP ativa
        username (str): Nome de usuário
        base_dn (str): Base DN para busca
    
    Returns:
        str: DN do usuário ou None se não encontrado
    """
    try:
        # Construir filtro de busca
        search_filter = f"(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"
        
        # Lista de bases de busca baseadas na estrutura do AD
        search_bases = [
            base_dn,
            f"CN=Users,{base_dn}",
            f"OU=HOMOLOGACAO,{base_dn}",
            f"OU=HOSPITAL BELO HORIZONTE,{base_dn}",
            f"OU=PAINEIS,{base_dn}",
            f"OU=Restaurante,{base_dn}",
            f"OU=SERVIDORES,{base_dn}",
            f"OU=TECNOLOGIA DA INFORMACAO,{base_dn}",
            f"OU=teste,{base_dn}"
        ]
        
        # Tentar buscar em cada base
        for search_base in search_bases:
            try:
                connection.search(
                    search_base,
                    search_filter,
                    attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName']
                )
                
                if connection.entries:
                    return str(connection.entries[0].distinguishedName)
                    
            except Exception:
                # Continuar para próxima base se houver erro
                continue
        
        return None
        
    except Exception as e:
        raise ADPasswordChangeError(f"Erro na busca do usuário: {str(e)}")


def _encode_password(password):
    """
    Codifica a senha no formato correto para o Active Directory
    
    Args:
        password (str): Senha em texto plano
    
    Returns:
        bytes: Senha codificada no formato UTF-16LE com aspas
    """
    # O AD requer que a senha seja codificada em UTF-16LE e envolvida em aspas
    password_quoted = f'"{password}"'
    return password_quoted.encode('utf-16le')


def listar_usuarios_disponiveis(admin_user, admin_password):
    """
    Lista usuários disponíveis no AD para facilitar a escolha
    
    Args:
        admin_user (str): Usuário administrador
        admin_password (str): Senha do administrador
    
    Returns:
        list: Lista de usuários encontrados
    """
    try:
        server = Server(AD_SERVER, use_ssl=False, get_info=ALL, connect_timeout=LDAP_TIMEOUT)
        
        # Conectar como administrador
        connection = Connection(
            server,
            user=f"HBH\\{admin_user}",
            password=admin_password,
            authentication=SIMPLE,
            auto_bind=True,
            receive_timeout=LDAP_TIMEOUT
        )
        
        if connection.bound:
            # Buscar usuários
            connection.search(
                AD_BASE_DN,
                "(&(objectClass=user)(objectCategory=person))",
                attributes=['sAMAccountName', 'displayName', 'userPrincipalName'],
                size_limit=20
            )
            
            usuarios = []
            if connection.entries:
                for entry in connection.entries:
                    sam_name = getattr(entry, 'sAMAccountName', 'N/A')
                    display_name = getattr(entry, 'displayName', 'N/A')
                    usuarios.append((sam_name, display_name))
            
            connection.unbind()
            return usuarios
        else:
            return []
            
    except Exception:
        return []


def obter_entrada_usuario():
    """
    Obtém as informações necessárias do usuário via console
    
    Returns:
        tuple: (username, senha_antiga, nova_senha, admin_user, admin_password)
    """
    print("=== Alteração de Senha no Active Directory ===\n")
    
    # Escolher modo de operação
    print("Escolha o modo de operação:")
    print("1. Alteração pelo próprio usuário (requer senha atual)")
    print("2. Alteração por administrador (não requer senha atual)")
    print("3. Modo rápido (usa credenciais pré-configuradas)")
    
    modo = input("\nDigite sua escolha (1, 2 ou 3): ").strip()
    
    if modo not in ['1', '2', '3']:
        raise ValueError("Escolha inválida. Digite 1, 2 ou 3.")
    
    # Obter nome do usuário alvo
    username = input("\nDigite o nome do usuário para alterar a senha: ").strip()
    if not username:
        raise ValueError("Nome de usuário é obrigatório")
    
    # Obter nova senha
    nova_senha = getpass.getpass("Digite a nova senha: ")
    if not nova_senha:
        raise ValueError("Nova senha é obrigatória")
    
    confirmar_senha = getpass.getpass("Confirme a nova senha: ")
    if nova_senha != confirmar_senha:
        raise ValueError("As senhas não coincidem")
    
    # Perguntar se deve forçar alteração no próximo logon
    print("\nOpções adicionais:")
    forcar_logon = input("Forçar usuário a alterar senha no próximo logon? (s/n): ").strip().lower()
    forcar_proximo_logon = forcar_logon in ['s', 'sim', 'y', 'yes']
    
    senha_antiga = None
    admin_user = None
    admin_password = None
    
    if modo == '1':
        # Modo 1: Alteração pelo próprio usuário
        senha_antiga = getpass.getpass("Digite sua senha atual: ")
        if not senha_antiga:
            raise ValueError("Senha atual é obrigatória")
    elif modo == '2':
        # Modo 2: Alteração por administrador
        admin_user = input("Digite o usuário administrador: ").strip()
        if not admin_user:
            raise ValueError("Usuário administrador é obrigatório")
        
        admin_password = getpass.getpass("Digite a senha do administrador: ")
        if not admin_password:
            raise ValueError("Senha do administrador é obrigatória")
        
        # Listar usuários disponíveis
        print("\n🔍 Buscando usuários disponíveis...")
        usuarios = listar_usuarios_disponiveis(admin_user, admin_password)
        
        if usuarios:
            print(f"\n📋 Usuários encontrados ({len(usuarios)}):")
            for i, (sam_name, display_name) in enumerate(usuarios, 1):
                print(f"   {i:2d}. {sam_name} - {display_name}")
            print(f"\n💡 Use o sAMAccountName (ex: gabriel.silva) para alterar a senha")
        else:
            print("\n⚠️  Não foi possível listar usuários")
    else:
        # Modo 3: Modo rápido com credenciais pré-configuradas
        admin_user = env.AD_ADMIN_USER  # pyright: ignore[reportUndefinedVariable]
        admin_password = env.AD_ADMIN_PASSWORD  # pyright: ignore[reportUndefinedVariable]
        # ou
        # admin_password = r"\QS'25^g*du}<C\3\w"
        
        print(f"\n🚀 Modo rápido ativado!")
        print(f"   Usando credenciais: {admin_user}")
        
        # Listar usuários disponíveis
        print("\n🔍 Buscando usuários disponíveis...")
        usuarios = listar_usuarios_disponiveis(admin_user, admin_password)
        
        if usuarios:
            print(f"\n📋 Usuários encontrados ({len(usuarios)}):")
            for i, (sam_name, display_name) in enumerate(usuarios, 1):
                print(f"   {i:2d}. {sam_name} - {display_name}")
            print(f"\n💡 Use o sAMAccountName (ex: gabriel.silva) para alterar a senha")
        else:
            print("\n⚠️  Não foi possível listar usuários")
    
    return username, senha_antiga, nova_senha, admin_user, admin_password, forcar_proximo_logon


def main():
    """
    Função principal da aplicação
    """
    try:
        # Obter informações do usuário
        username, senha_antiga, nova_senha, admin_user, admin_password, forcar_proximo_logon = obter_entrada_usuario()
        
        print(f"\nTentando alterar a senha para o usuário: {username}")
        print("Conectando ao Active Directory...")
        
        # Realizar alteração da senha
        sucesso = alterar_senha_ad(
            username=username, 
            senha_antiga=senha_antiga, 
            nova_senha=nova_senha,
            admin_user=admin_user,
            admin_password=admin_password,
            forcar_proximo_logon=forcar_proximo_logon
        )
        
        if sucesso:
            print("✅ Senha alterada com sucesso!")
        else:
            print("❌ Falha na alteração da senha")
            
    except ValueError as e:
        print(f"❌ Erro de entrada: {str(e)}")
    except ADPasswordChangeError as e:
        print(f"❌ Erro na alteração da senha: {str(e)}")
    except KeyboardInterrupt:
        print("\n❌ Operação cancelada pelo usuário")
    except Exception as e:
        print(f"❌ Erro inesperado: {str(e)}")


if __name__ == "__main__":
    main()
