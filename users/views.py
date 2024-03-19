from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .users import create_user, read_user, update_user, delete_user, connect_user, disconnect_user

from .users import create_user, read_user, update_user, delete_user, connect_user, disconnect_user

@api_view(['POST', 'GET','PUT','DELETE','PATCH'])
def users_view(request):
    method_switch = {
        "POST": create_user,
        "GET": read_user,
        "PUT": update_user,
        "DELETE": delete_or_disconnect_user,
        "PATCH": connect_user
    }

    handler = method_switch.get(request.method)

    if handler:
        return handler(request)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)

def delete_or_disconnect_user(request):
    logout = request.data.get('logout', False)
    if logout:
        return disconnect_user(request)
    else:
        return delete_user(request)
