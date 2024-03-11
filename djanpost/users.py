from datetime import timedelta, datetime
import secrets
from django.http import HttpResponse, JsonResponse
import jwt
from requests import Response
from rest_framework.decorators import api_view
from djanpost.models import JWT, aws_credentials, users
from django.db import models
import hashlib

# users stuff all stored here

def add_user(request):
    got_name = request.data.get('name', 'user_name')
    got_email = request.data.get('email', 'user_email')
    got_password = request.data.get('password', 'user_password')
    got_recovery_answer = request.data.get('recovery','user_recovery')
    print("fuck it")
    hashed_password = hashlib.sha256(got_password.encode()).hexdigest()

    if got_name != "user_name":
        new_user = users(name=got_name, email=got_email, password=hashed_password, recovery_answer=got_recovery_answer)
    try:
        new_user.save()
        return HttpResponse("User saved succesfully", status=200)
    except Exception as e:
        print("something went wrong .. 508"+"\n" + str(e))
        return HttpResponse("user already here", status=401) 

def get_user_info(request):
    try:
        token = request.data.get('token')
        if not token:
            raise ValueError("Token is required")

        user_jwt = JWT.objects.get(token=token)
        user = users.objects.get(id=user_jwt.user_id)

        return JsonResponse({"id": user.id, "name": user.name, "email": user.email, "recovery":user.recovery_answer}, status=200)

    except JWT.DoesNotExist:
        return JsonResponse({"error": "JWT not found"}, status=401)

    except users.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=401)

    except ValueError as ve:
        return JsonResponse({"error": str(ve)}, status=400)

    except Exception as e:
        return JsonResponse({"error": "Something went wrong"}, status=500)
    
    
def show_users(request):
    try:
        users_data = users.objects.values('name', 'email', 'password', 'recovery_answer')

        # Convert the QuerySet to a list of dictionaries
        users_list = [
            {
                'name': user['name'],
                'email': user['email'],
                'recovery_answer': user['recovery_answer']
            }
            for user in users_data
        ]

        return JsonResponse(users_list, safe=False)  # Pass users_list instead of users_data
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    
    
#check user
def verify_user(request):
    try:
        email = request.data.get('email', '')
        password = request.data.get('password', '')

        # Perform basic validation (not a replacement for comprehensive validation)
        if not email or not password:
            return JsonResponse({'error': 'Email and password are required fields'}, status=400)

        # Get the user with the provided email
        try:
            user = users.objects.get(email=email)
        except users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=401)

        # Manually check the hashed password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if user.password != hashed_password:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
        
        # delete previous jwt
        try:
            previous_jwt = JWT.objects.get(user=user)
            previous_jwt.delete()
        except JWT.DoesNotExist:
            pass
        
        secret_token=generate_jwt(user.id)
        # User authenticated, return success response (consider using appropriate status code)
        return JsonResponse({"message": "Authentication successful.", "token":secret_token}, status=200)

    except Exception as e:
        print(e)
        # Log the error securely (avoid revealing sensitive information)
        return JsonResponse({"error": "Internal server error"}, status=500)
    
def logout(request):
    token = request.data.get('token', None)

    if not token:
        return JsonResponse({"error": "Token not provided"}, status=400)

    try:
        previous_jwt = JWT.objects.get(token=token)
        previous_jwt.delete()
        return JsonResponse({"message": "Logged out successfully"}, status=200)

    except JWT.DoesNotExist:
        return JsonResponse({"error": "Invalid token"}, status=404)
    
def add_aws_credentials(request):
    user_id = request.data.get('id',None)
    token = request.data.get('token',None)
    access_key_id = request.data.get('access_key_id',None)
    secret_access_key = request.data.get('secret_access_key',None)
    if not user_id or not token or not secret_access_key or not access_key_id:
        return JsonResponse({'error': 'Invalid Request'}, status=401)
    
    # get user by id
    try:
        user = users.objects.get(id=user_id)
    except users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    #check token
    jwt=JWT.objects.get(user=user)
    if(token != jwt.token or datetime.utcnow() > jwt.expiration_time):
       return JsonResponse({"message":"something went wrong, please relogin"}, status=401)
    
    # save new aws credentials
    new_credentials = aws_credentials(user=user, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    new_credentials.save()
    return JsonResponse({"message":"credentials saved successfully"}, status=200)


def verify_request(user_id, token):
    try:
        # Get the JWT entry from the database
        jwt_entry = JWT.objects.get(user__id=user_id, token=token)


        # Check if the token is expired
        if jwt_entry.expiration_time < datetime.utcnow():
            jwt_entry.delete()  # Delete the expired token
            return "Invalid request, please re-login."

        return "Request verified successfully."

    except JWT.DoesNotExist:
        return "JWT not found in the database. Please re-login."
    except Exception as e:
        return f"Error: {e}"
    
def generate_jwt(user_id):
    # Generate a random secret key (you may want to store this securely)
    secret_key = secrets.token_urlsafe(32)

    # Set the expiration time for the token (e.g., 1 hour from now)
    expiration_time = datetime.utcnow() + timedelta(hours=1)

    # Create the payload
    payload = {
        'user_id': user_id,
        'exp': expiration_time,
    }

    # Generate the JWT
    jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')

    # Store the JWT in the database along with its expiration time
    JWT.objects.create(user_id=user_id, token=jwt_token, expiration_time=expiration_time)

    return jwt_token


          
        
       