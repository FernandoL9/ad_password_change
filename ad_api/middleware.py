class FixHostHeaderMiddleware:
    """
    Sanitiza o header HTTP_HOST antes da validação do Django,
    substituindo underscores por hífens para contornar a restrição
    RFC 1034/1035 imposta pelo Django 5+.

    Necessário quando o hostname externo (ex: Cloudflare Tunnel) usa
    underscore no subdomínio (ex: integracao_ghas.dominio.com.br).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.META.get('HTTP_HOST', '')
        if '_' in host:
            request.META['HTTP_HOST'] = host.replace('_', '-')
        return self.get_response(request)
