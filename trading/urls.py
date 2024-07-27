from django.urls import path
from . import views

handler403 = views.csrf_failure

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("register", views.register, name="register"),
    path("search", views.search, name = "search"),
    path("buy", views.buy, name = "buy"),
    path("sell", views.sell, name = "sell"),
    path("activate/<uidb64>/<token>", views.activateUser, name = "activate"),
    path("favicon.ico", views.favicon)
]