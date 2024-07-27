from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, FileResponse, HttpRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import User, Transaction
from django.contrib.sites.shortcuts import get_current_site
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
import yfinance as yf
import plotly.graph_objects as go
from requests.exceptions import HTTPError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
import threading
from django.contrib import messages
from decimal import Decimal
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET
from django.middleware.csrf import CsrfViewMiddleware
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseForbidden
from django.views.decorators.csrf import csrf_protect


@require_GET
@cache_control(max_age=60 * 60 * 24, immutable=True, public=True)  # one day
def favicon(request: HttpRequest) -> HttpResponse:
    file = (settings.BASE_DIR / "static" / "favicon.png").open("rb")
    return FileResponse(file)

def csrf_failure(request, reason=""):
    """
    Custom CSRF failure handler.
    """
    # Assuming you have a 'dashboard' URL name, you can change this to your desired URL
    messages.error(request, "CSRF token validation failed. Please refresh the page and try again.")
    return HttpResponseRedirect(reverse('dashboard'))


@csrf_protect
def dashboard(request):
    if request.user.is_authenticated and request.user.emailVerified:
        allShares = Transaction.objects.filter(user = request.user)
        total = User.objects.get(pk = request.user.id).balance
        for share in allShares:
            price = Decimal(yf.Ticker(share.stock).info['currentPrice'])
            total += Decimal(share.shares) * price
            update = Transaction.objects.get(user = request.user.id, stock = share.stock)
            update.currentValue = Decimal(share.shares) * price
            update.save()

        return render(request, "trading/dashboard.html", {
            "shares": allShares,
            "total": total,
        })
    else:
        return render(request, "trading/login.html")

@csrf_protect
def login_view(request):
    if request.method == "POST":

        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        # First, check if the user exists with the given username
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'trading/login.html', {
                "message": "Username does not exist."
            })

        # Check if the user is authenticated
        user = authenticate(request, username=username, password=password)
        if user is None:
            return render(request, 'trading/login.html', {
                'message': "Invalid password."
            })

        # Check if the email is verified
        if not user.emailVerified:
            return render(request, 'trading/login.html', {
                "message": "Email not verified. Please check your email for the verification link."
            })

        # Log the user in if all checks pass
        login(request, user)
        return HttpResponseRedirect(reverse("dashboard"))
    else:
        return render(request, "trading/login.html")

@csrf_protect
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("dashboard"))

@csrf_protect
def verifyEmail(request, user):
    currSite = request.get_host()
    emailSubject = "Titan - Verification email"
    emailBody = render_to_string('trading/activate.html', {
        'user': user,
        'domain': currSite,
        'uid': urlsafe_base64_encode(force_bytes(user.id)),
        'token': generate_token.make_token(user)
    })

    email = EmailMessage(subject=emailSubject, body=emailBody,
                         from_email=settings.EMAIL_FROM_USER,
                         to=[user.email]
                         )

    email.send()

@csrf_protect
def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(request, "trading/register.html", {
                "message": "Passwords must match."
            })
        if len(password) < 8:
            return render(request, "trading/register.html", {
                "message": "Password must be at least 8 characters long."
            })
        if User.objects.filter(username=username).exists():
            return render(request, "trading/register.html", {
                "message": "Username already taken."
            })
        if User.objects.filter(email=email).exists():
            return render(request, "trading/register.html", {
                "message": "There is already an account with this email address."
            })

        # Attempt to create new user
        try:
            validate_email(email)
            user = User.objects.create_user(username, email, password)
            user.save()
            verifyEmail(request, user)
            messages.success(request, "Check your email for the verification link.")
            return redirect("login")
        except ValidationError as e:
            return render(request, "trading/register.html", {
                "message": "Email invalid."
            })
        except IntegrityError:
            return render(request, "trading/register.html", {
                "message": "Username already taken."
            })
    else:
        return render(request, "trading/register.html")


@csrf_protect
def is_valid_ticker(request, ticker):
    stock = yf.Ticker(ticker)
    info = stock.info
    essential_keys = ['currentPrice', 'shortName']
    if not info or any(key not in info for key in essential_keys):
        return False
    return True


@csrf_protect
def get_stock_history(request, stock, period):
    history = stock.history(period=period)
    if history.empty:
        raise ValueError(f"No {period} historical data found for the ticker")
    return history


@csrf_protect
def search(request):
    if request.method == "POST":
        ticker = request.POST['ticker'].upper()
    else:
        ticker = request.GET['ticker'].upper()
    currentShares = 0

    if request.user.is_authenticated:
        if Transaction.objects.filter(user=request.user, stock=ticker).exists():
            oldBuy = Transaction.objects.get(user=request.user, stock=ticker)
            currentShares = oldBuy.shares

    try:
        if not is_valid_ticker(request, ticker):
            raise ValueError("Invalid ticker symbol")

        stock = yf.Ticker(ticker)
        info = stock.info

        # 1 year history
        oneYr = get_stock_history(request, stock, "1y")
        fig1 = go.Figure(data=go.Scatter(x=oneYr.index, y=oneYr['Close']))
        graph1 = fig1.to_html(full_html=False, default_width='620px')

        # 6 months history
        sixMo = get_stock_history(request, stock, "6mo")
        fig2 = go.Figure(data=go.Scatter(x=sixMo.index, y=sixMo['Close']))
        graph2 = fig2.to_html(full_html=False, default_width='620px')

        # 1 month history
        oneMo = get_stock_history(request, stock, "1mo")
        fig3 = go.Figure(data=go.Scatter(x=oneMo.index, y=oneMo['Close']))
        graph3 = fig3.to_html(full_html=False, default_width='620px')

        return render(request, "trading/search.html", {
            "info": info,
            "oneYr": graph1,
            "sixMo": graph2,
            "oneMo": graph3,
            "currentShares": currentShares
        })


    except ValueError as ve:
        messages.error(request, str(ve))
        return HttpResponseRedirect(reverse("dashboard"))
    except Exception as e:
        messages.error(request, str(e))
        return HttpResponseRedirect(reverse("dashboard"))


@csrf_protect
def buy(request):
    if request.method == "POST":
        #Get information
        shares = Decimal(request.POST['shares'])
        ticker = request.POST['ticker']
        price = Decimal(request.POST['price'])
        user = request.user
        currentUser = User.objects.get(pk = user.id)
        balance = currentUser.balance

        #Check if user has enough money
        if balance < (shares * price):
            try:
                currentShares = 0
                stock = yf.Ticker(ticker)
                info = stock.info
                #One yr
                oneYr = stock.history(period = "1y")
                fig1 = go.Figure(data = go.Scatter(x = oneYr.index,  y = oneYr['Close']))
                graph1 = fig1.to_html(full_html=False)

                #6 months
                six = stock.history(period = "6mo")
                fig2 = go.Figure(data = go.Scatter(x = six.index,  y = six['Close']))
                graph2 = fig2.to_html(full_html=False)

                #1 month
                one = stock.history(period = "1mo")
                fig3 = go.Figure(data = go.Scatter(x = one.index,  y = one['Close']))
                graph3 = fig3.to_html(full_html=False)

                if Transaction.objects.filter(user = user, stock = ticker).exists():
                    currentShares += 1

                return render(request, "trading/search.html", {
                    "info": info,
                    "oneYr": graph1,
                    "sixMo": graph2,
                    "oneMo": graph3,
                    "message": "Insuficient funds.",
                    "currentShares": currentShares
                })
            except HTTPError:
                messages.error("Invalid ticker.")
                return HttpResponseRedirect(reverse("dashboard"))

        #Check if user has the stock
        if Transaction.objects.filter(user = user, stock = ticker).exists():
            oldBuy = Transaction.objects.get(user = user, stock = ticker)
            oldBuy.shares += shares
            oldBuy.save()
            oldBuy.currentValue = oldBuy.shares * price
            oldBuy.save()

        else:
            newTransaction = Transaction(user = user, stock = ticker, shares = shares)
            newTransaction.save()
            newTransaction.currentValue = newTransaction.shares * price
            newTransaction.save()

        #Update balance and return dashboard
        currentUser.balance = balance - (shares * price)
        currentUser.save()
        return HttpResponseRedirect('.')

@csrf_protect
def sell(request):
    if request.method == "POST":
        shares = Decimal(request.POST['shares'])
        ticker = request.POST['ticker']
        price = Decimal(request.POST['price'])
        user = request.user
        currentUser = User.objects.get(pk = user.id)
        balance = currentUser.balance

        oldBuy = Transaction.objects.get(user = user, stock = ticker)
        if shares == oldBuy.shares:
            oldBuy.delete()
        else:
            oldBuy.shares -= shares
            oldBuy.save()
            oldBuy.currentValue = oldBuy.shares * price
            oldBuy.save()
        currentUser.balance = balance + (shares * price)
        currentUser.save()
        return HttpResponseRedirect('.')


@csrf_protect
def activateUser(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user, token):
        user.emailVerified = True
        user.save()
        login(request, user)
        messages.success(request, "Email Verified Successfully!")
        return HttpResponseRedirect(reverse("dashboard"))

    # If user is None or token is invalid, render the login page with an error message
    if request.user.is_authenticated and request.user.emailVerified:
        return HttpResponseRedirect(reverse("dashboard"))
    else:
        return render(request, "trading/login.html", {
            "message": "Email verification failed or the activation link is invalid."
        })