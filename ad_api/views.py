from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_GET


@require_GET
def health(request):
    now = timezone.now()
    local = timezone.localtime(now)
    return JsonResponse({
        "status": "ok",
        "server_time": local.isoformat(),
        "timezone": timezone.get_current_timezone_name(),
    })
