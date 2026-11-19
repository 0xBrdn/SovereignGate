from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache


@never_cache
def healthz(_request):
    return JsonResponse({"status": "ok", "service": "sovereigngate-platform"})


def csrf_failure(request, reason=""):
    return render(request, "403.html", {"reason": "Your session token expired. Reload the page and try again."}, status=403)
