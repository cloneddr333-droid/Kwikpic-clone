from django.contrib.auth import authenticate, login, logout
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from accounts.serializers import SignupSerializer


@api_view(["POST"])
@permission_classes([AllowAny])
def signup(request):
    """Photographer self-signup. Creates User + linked Photographer profile."""
    serializer = SignupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key, "email": user.email}, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    email = request.data.get("email")
    password = request.data.get("password")
    user = authenticate(request, username=email, password=password)
    if user is None:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key, "email": user.email})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    request.user.auth_token.delete()
    return Response({"message": "Logged out"})
