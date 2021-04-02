from django.urls import path
from . import views

urlpatterns = [
    path('api/users/',views.ListUsers.as_view()),
    path('api/token/auth/', views.CustomAuthToken.as_view()),
    path('',views.index,name="index"),
    path('register/',views.register,name="register"),
    path('login/',views.enter_user,name="login"),
    path('logout/',views.kick_user,name="logout")
]
