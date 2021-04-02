from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User,auth
from django.contrib.auth.views import LoginView
from django.contrib.auth import authenticate,login
from django.contrib.auth.hashers import check_password
from django.contrib.auth import logout
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response 
import re
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.contrib import messages


class ListUsers(APIView):
    """
    View to list all users in the system.

    * Requires token authentication.
    * Only admin users are able to access this view.
    """
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        emails = [user.email for user in User.objects.all()]
        return Response(emails)


class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })


def index(request):
    return render(request,'l.html')

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
def check(email):
    if re.search(regex,email):
        return True
    else:
        return False

reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
def checks_passwd(password1):
    if re.search(reg,password1):
        return True
    else:
        return False

def register(request):
    first_name=""
    last_name=""
    username=""
    password=""
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('email')
        password = request.POST.get('password')
        if checks_passwd(password) == True and User.objects.filter(username=username).exists() == False:
            user = User.objects.create_user(username=username,first_name=first_name,last_name=last_name,password=password)
            user.save()
            print(first_name,last_name,username,password)
            messages.success(request,"Welcome")
            return redirect('/')
        else:
            # user.save(commit=False)
            messages.info(request,"User Already Exists")
            return redirect('register')
            # return HttpResponse("Invalid Credentials")
    else:
        return render(request,'try.html')

def enter_user(request):
    if request.method == "POST":
        username = request.POST['email']
        password1 = request.POST['password1']
        user = authenticate(request,username=username, password=password1)
        # if username == None or password1 == None:
        #     return Response({'error':'Please provide both Username and Password'},status=HTTP_400_BAD_REQUEST)
        # if not user:
        #     return Response({'error':'Invalid Credentials'},status=HTTP_400_NOT_FOUND)
        print(user)
        if user is not None:
            login(request,user)
            return redirect('/')
        else:
            messages.info(request,"Invalid Credentials")
            return redirect('login')
    else:
        return render(request,'registrations/login.html')

def kick_user(request):
    return HttpResponse("Logged Out")

