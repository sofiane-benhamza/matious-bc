from datetime import timedelta, datetime
import random
import secrets
import string
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from django.db import models
from django.views.decorators.csrf import csrf_exempt
import jwt
from requests import Response
from rest_framework.decorators import api_view
from .models import JWT, aws_credentials, users
import hashlib
from django.shortcuts import get_object_or_404
from django.utils import timezone

# Create your views here.
def main(request, name):
    result = {"message": f"Welcome, {name}! This is the main page"}
    return HttpResponse(result)

# users stuff

@api_view(['POST'])
def add_user_view(request):
    return add_user(request)

@api_view(['POST'])
def get_user_info_view(request):
    return get_user_info(request)

@api_view(['POST'])
def update_user_view(request):
    return update_user(request)

    
@api_view(['POST'])
def show_users_view(request):
    return show_users(request)
    
#check user
@api_view(['POST'])
def verify_user_view(request):
    return verify_user(request)

@api_view(['POST'])
def logout_view(request):
    return logout(request)
    
@api_view(['POST'])
def add_credentials_view(request):
    return add_credentials(request)

# Funtions :

# users 
def update_user(request):
    got_token = request.data.get('token',None)
    got_name = request.data.get('name', None)
    got_email = request.data.get('email', None)
    got_old_password = request.data.get('oldPassword', None)
    got_new_password = request.data.get('newPassword', None)
    got_recovery_answer = request.data.get('recovery',None)

    if not got_token:
        return HttpResponse("something went wrong ... 452", status=401)        
    try:
        user_jwt = JWT.objects.get(token=got_token)
        user = user_jwt.user
        hashed_password = hashlib.sha256(got_old_password.encode()).hexdigest()
        if user.password != hashed_password:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
        
        # Verify user identity using the token
        if user.id != user_jwt.user_id:
            return JsonResponse({'error': 'Invalid user for the provided token'}, status=401)

        # Verify old password
        hashed_old_password = hashlib.sha256(got_old_password.encode()).hexdigest()
        if user.password != hashed_old_password:
            return JsonResponse({'error': 'Invalid old password'}, status=401)
        # Update user attributes
        user.name = got_name or user.name
        user.email = got_email or user.email
        user.recovery_answer = got_recovery_answer or user.recovery_answer

        # Update the password if a new one is provided
        if got_new_password:
            user.password = hashlib.sha256(got_new_password.encode()).hexdigest()

        # Save the changes
        user.save()
        return HttpResponse("User saved succesfully", status=200)
    except Exception as e:
        print("something went wrong .. 508"+"\n" + str(e))
        return HttpResponse("user already here", status=401)

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
    
def add_user(request):
    got_name = request.data.get('name', 'user_name')
    got_email = request.data.get('email', 'user_email')
    got_password = request.data.get('password', 'user_password')
    got_recovery_answer = request.data.get('recovery','user_recovery')
    hashed_password = hashlib.sha256(got_password.encode()).hexdigest()

    if got_name != "user_name":
        new_user = users(name=got_name, email=got_email, password=hashed_password, recovery_answer=got_recovery_answer)
    try:
        new_user.save()
        return HttpResponse("User saved succesfully", status=200)
    except Exception as e:
        print("something went wrong .. 508"+"\n" + str(e))
        return HttpResponse("user already here", status=401)
    
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
    
def get_user_info(request):
    try:
        token = request.data.get('token')
        if not token:
            raise ValueError("Token is required")

        user_jwt = JWT.objects.get(token=token)
        user = users.objects.get(id=user_jwt.user_id)

        return JsonResponse({"name": user.name, "email": user.email, "recovery":user.recovery_answer}, status=200)

    except JWT.DoesNotExist:
        return JsonResponse({"error": "JWT not found"}, status=401)

    except users.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=401)

    except ValueError as ve:
        return JsonResponse({"error": str(ve)}, status=400)

    except Exception as e:
        return JsonResponse({"error": "Something went wrong"}, status=500)
    
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

# credentials cloud providers
def add_credentials(request):
    got_cloud = request.data.get('cloud', None)
    got_token = request.data.get('token', None)
    access_key_id = request.data.get('access_key_id', None)
    secret_access_key = request.data.get('secret_access_key', None)

    print("i am here")
    # Check for required fields
    if not all([got_token, got_cloud, secret_access_key, access_key_id]):
        return JsonResponse({'error': 'Invalid Request'}, status=401)

    # Get user by JWT
    user_jwt = get_object_or_404(JWT, token=got_token)
    user = user_jwt.user

    # Check token expiration
    if got_token != user_jwt.token or timezone.now() > user_jwt.expiration_time:
        return JsonResponse({"message": "Something went wrong, please re-login"}, status=401)

    # Create new credentials based on the cloud provider
    if got_cloud == "aws":
        new_credentials = aws_credentials(
            user=user,
            unique_name=secrets.token_hex(7),
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )
    elif got_cloud == "gcp":
        pass  # Add GCP logic here
    elif got_cloud == "azure":
        pass  # Add Azure logic here
    else:
        pass  # Handle other cloud providers

    print("i am here >" )
    # Save new credentials
    new_credentials.save()
    return JsonResponse({"message": "Credentials saved successfully"}, status=200)


