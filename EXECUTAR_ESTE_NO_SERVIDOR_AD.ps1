# ============================================================
# CONFIGURACAO AUTOMATICA DE LDAPS
# ============================================================
# INSTRUCOES:
# 1. COPIE ESTE ARQUIVO PARA O SERVIDOR AD (192.168.100.23)
# 2. Clique com BOTAO DIREITO -> "Executar como Administrador"
# 3. Aguarde a conclusao (2-5 minutos)
# 4. Aguarde mais 10 minutos para ativacao
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURACAO AUTOMATICA DE LDAPS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar se e Administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERRO: Execute como Administrador!" -ForegroundColor Red
    Write-Host "   Botao direito -> Executar como Administrador" -ForegroundColor Yellow
    Read-Host "Pressione Enter para sair"
    exit 1
}

# Obter informacoes do servidor
$hostname = $env:COMPUTERNAME
$fqdn = [System.Net.Dns]::GetHostByName($hostname).HostName
$ipAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"}).IPAddress
$ipAddress = ($ipAddresses | Where-Object {$_ -like "192.168.*"})[0]
if (-not $ipAddress) { $ipAddress = $ipAddresses[0] }

Write-Host "Informacoes do Servidor:" -ForegroundColor Green
Write-Host "   Nome: $hostname" -ForegroundColor White
Write-Host "   FQDN: $fqdn" -ForegroundColor White
Write-Host "   IP: $ipAddress" -ForegroundColor White
Write-Host ""

# Passo 1: Criar certificado
Write-Host "PASSO 1: Criando certificado SSL..." -ForegroundColor Yellow
try {
    # Verificar se ja existe certificado valido
    $existingCert = Get-ChildItem cert:\LocalMachine\My | Where-Object {
        $_.Subject -like "*$hostname*" -and $_.NotAfter -gt (Get-Date)
    } | Select-Object -First 1
    
    if ($existingCert) {
        Write-Host "   Certificado existente encontrado: $($existingCert.Thumbprint)" -ForegroundColor Gray
        $cert = $existingCert
    } else {
        $cert = New-SelfSignedCertificate `
            -Subject "CN=$hostname" `
            -DnsName @($hostname, $fqdn, $ipAddress) `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -KeyUsage DigitalSignature, KeyEncipherment `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(1) `
            -ErrorAction Stop
        
        Write-Host "   Certificado criado: $($cert.Thumbprint)" -ForegroundColor Green
    }
} catch {
    Write-Host "   ERRO ao criar certificado: $_" -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    exit 1
}

# Passo 2: Adicionar ao Trusted Root
Write-Host ""
Write-Host "PASSO 2: Configurando certificado no Trusted Root..." -ForegroundColor Yellow
try {
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    
    # Verificar se ja existe
    $exists = $rootStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $cert.Thumbprint, $false)
    if ($exists.Count -eq 0) {
        $rootStore.Add($cert)
        Write-Host "   Certificado adicionado ao Trusted Root" -ForegroundColor Green
    } else {
        Write-Host "   Certificado ja esta no Trusted Root" -ForegroundColor Gray
    }
    
    $rootStore.Close()
} catch {
    Write-Host "   AVISO: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Passo 3: Configurar firewall
Write-Host ""
Write-Host "PASSO 3: Configurando firewall..." -ForegroundColor Yellow
try {
    $firewallRule = Get-NetFirewallRule -DisplayName "LDAPS" -ErrorAction SilentlyContinue
    if (-not $firewallRule) {
        New-NetFirewallRule -DisplayName "LDAPS" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow | Out-Null
        Write-Host "   Regra de firewall criada (porta 636)" -ForegroundColor Green
    } else {
        Write-Host "   Regra de firewall ja existe" -ForegroundColor Gray
    }
} catch {
    Write-Host "   AVISO ao configurar firewall: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Passo 4: Reiniciar servicos
Write-Host ""
Write-Host "PASSO 4: Reiniciando servicos..." -ForegroundColor Yellow
try {
    Write-Host "   Reiniciando NTDS (Active Directory)..." -ForegroundColor Gray
    Restart-Service NTDS -Force -ErrorAction SilentlyContinue
    
    Write-Host "   Reiniciando NETLOGON..." -ForegroundColor Gray
    Restart-Service NETLOGON -Force -ErrorAction SilentlyContinue
    
    Write-Host "   Servicos reiniciados" -ForegroundColor Green
} catch {
    Write-Host "   AVISO: Alguns servicos podem nao ter sido reiniciados" -ForegroundColor Yellow
    Write-Host "      Isso e normal em alguns ambientes" -ForegroundColor Gray
}

# Passo 5: Verificar porta
Write-Host ""
Write-Host "PASSO 5: Verificando configuracao..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

try {
    $listener = Get-NetTCPConnection -LocalPort 636 -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        Write-Host "   Porta 636 (LDAPS) esta ESCUTANDO!" -ForegroundColor Green
    } else {
        Write-Host "   Porta 636 ainda nao esta ativa" -ForegroundColor Yellow
        Write-Host "      Isso pode levar ate 10 minutos - e normal!" -ForegroundColor Gray
    }
} catch {
    Write-Host "   Nao foi possivel verificar a porta agora" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURACAO CONCLUIDA!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "PROXIMOS PASSOS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. AGUARDE 10 MINUTOS para o certificado ser ativado" -ForegroundColor White
Write-Host ""
Write-Host "2. No seu computador, atualize config.py:" -ForegroundColor White
Write-Host "   AD_SERVER = 'ldaps://$ipAddress:636'" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Teste a conexao:" -ForegroundColor White
Write-Host "   python testar_ldaps.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Execute o reset de senha:" -ForegroundColor White
Write-Host "   python ad_password_change.py" -ForegroundColor Cyan
Write-Host ""

Read-Host "Pressione Enter para sair"
