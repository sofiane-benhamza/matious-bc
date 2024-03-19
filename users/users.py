from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import users
import hashlib
from tokenAuth.views import check_token,create_token,delete_token
from tokenAuth.models import tokenAuth


def create_user(request):
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    email = request.data.get('email')
    password = request.data.get('password')
    role = request.data.get('role')    

    if not (first_name and last_name and email and password and role):
        return Response({"error": "Missing required fields"}, status=400)

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        new_user = users.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            role=role,
        )
        return Response({'message': 'User created successfully'}, status=201)
    except Exception as e:
        # Log the error
        print('Something went wrong: ', e)
        return Response({'error': 'something went wrong ... 804'}, status=401)

def read_user(request):
    try:
        got_token = request.data.get('token', None)
        if check_token(got_token):
            #get user by token
            user = users.objects.get(id=(tokenAuth.objects.get(token=got_token)).user.id)

        return JsonResponse({"fname": user.first_name,"lname":user.last_name ,"email": user.email, "role":user.role}, status=200)

    except Exception as e:
        return JsonResponse({"error": "Something went wrong ... 806"}, status=500)

def update_user(request): 
    #checking request
    got_token = request.data.get('token',None)
    if not check_token(got_token):
        return JsonResponse({'error':'something went wrong ... 810'},status=401)

    got_first_name = request.data.get('fname', None)
    got_last_name = request.data.get('lname', None)
    got_email = request.data.get('email', None)
    got_old_password = request.data.get('oldPassword', '')
    got_new_password = request.data.get('newPassword', None)
    got_role = request.data.get('role',None)

    try:
        # get user by token
        user = users.objects.get(id=(tokenAuth.objects.get(token=got_token)).user.id)
       


        # Update user attributes
        user.first_name = got_first_name or user.first_name
        user.last_name = got_first_name or user.last_name
        user.email = got_email or user.email
        user.role = got_role or user.role
        if got_new_password and got_old_password:
            # check old password
            hashed_password = hashlib.sha256(got_old_password.encode()).hexdigest()
            if user.password != hashed_password:
                return JsonResponse({'error': 'something went wrong ... 817'}, status=401)
            user.password = hashlib.sha256(got_new_password.encode()).hexdigest()

        # Save the changes
        user.save()
        return JsonResponse({"message":"User Updated succesfully"}, status=200)
    except Exception as e:
        print("something went wrong .. 824"+"\n" + str(e))
        return JsonResponse({"error":"user already here"}, status=401)

def delete_user(request):
    got_token = request.data.get('token',None)
    if not check_token(got_token):
        return JsonResponse({'error':'something went wrong ... 828'},status=401)
    delete = request.data.get('delete',False)
    
    if delete:
        try:
            # get user by token
            user = users.objects.get(id=(tokenAuth.objects.get(token=got_token)).user.id)
            user.delete()
            return Response({'message': 'User Deleted successfully'}, status=202)
        except Exception as e:
            print(e)
            return JsonResponse({"error": "something went wrong ... 832"}, status=401)
    return JsonResponse({"error": "something went wrong ... 834"}, status=401)

def connect_user(request):
    try:
        got_email = request.data.get('email', None)
        got_password = request.data.get('password', None)

        # Perform basic validation (not a replacement for comprehensive validation)
        if not ( got_email and got_password):
            return JsonResponse({'error': 'something went wrong ... 838'}, status=400)

        # Get the user with the provided email
        try:
            user = users.objects.get(email=got_email)
        except users.DoesNotExist:
            return JsonResponse({'error': 'something went wrong ... 842'}, status=401)

        # Manually check the hashed password
        hashed_password = hashlib.sha256(got_password.encode()).hexdigest()
        if user.password != hashed_password:
            return JsonResponse({'error': 'Authentication failed ... 846'}, status=401)
        
        # delete previous jwt
        try:
            previous_jwt = tokenAuth.objects.get(user=user)
            previous_jwt.delete()
        except tokenAuth.DoesNotExist:
            pass
        
        secret_token=create_token(user)
        # User authenticated, return success response (consider using appropriate status code)
        return JsonResponse({"message": "Authentication successful.", "token":secret_token}, status=200)

    except Exception as e:
        print(e)
        return JsonResponse({"error": "Internal server error"}, status=500)

def disconnect_user(request):
    got_token = request.data.get('token',None)
    if not check_token(got_token):
        return JsonResponse({'error':'something went wrong ... 838'},status=401)

    try:
        previous_jwt = tokenAuth.objects.get(token=got_token)
        previous_jwt.delete()
        return JsonResponse({"message": "Logged out successfully"}, status=200)
    except tokenAuth.DoesNotExist:
        return JsonResponse({"error": "Invalid token"}, status=404)