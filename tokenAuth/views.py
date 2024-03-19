from datetime import timedelta, datetime
import secrets
import jwt
from django.http import JsonResponse
from .models import tokenAuth  # Assuming tokenAuth is used in the generate_token function
from users.models import users
from django.core.exceptions import ObjectDoesNotExist  # Import ObjectDoesNotExist exception

#generate token (login)
def create_token(user):
    # Generate a random secret key (you may want to store this securely)
    secret_key = secrets.token_urlsafe(32)

    # Set the expiration time for the token (e.g., 1 hour from now)
    expiration_time = datetime.utcnow() + timedelta(hours=1)

    # Create the payload
    payload = {
        'email': user.email,
        'exp': expiration_time,
    }

    # Generate the JWT
    jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')

    # Store the JWT in the database along with its expiration time
    tokenAuth.objects.create(user=user, token=jwt_token, expiration_time=expiration_time)

    return jwt_token

#delete token (logout)
def delete_token(token):
    token = request.data.get('token', None)

    if not token:
        return JsonResponse({"error": "Token not provided"}, status=400)

    try:
        previous_jwt = JWT.objects.get(token=token)
        previous_jwt.delete()
        return JsonResponse({"message": "Logged out successfully"}, status=200)

    except JWT.DoesNotExist:
        return JsonResponse({"error": "Invalid token"}, status=404)

#check connectivity (every request)
def check_token(token):
    if not token:
        HttpResponse({'error':'something went wrong ... 372'}, status=401)
    try:
        user_jwt = tokenAuth.objects.get(token=token)
        user = users.objects.get(id=user_jwt.user.id)  # Access user_id directly

    except ObjectDoesNotExist:
        return False
    except Exception as e:
        print('Exception:', e)  # Print exception details
        return False
    
    return True
