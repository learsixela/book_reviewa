from django.db import models
import re
import bcrypt
from django.db.models.deletion import CASCADE
from django.db.models.fields import CharField

# Create your models here.
class UserManager(models.Manager):
    def basic_validator(self, postData):
        errores = {}
        if len(User.objects.filter(email=postData['email'])) > 0:
            errores['existe'] = "Email ya registrado"
        else:
            if len(postData['nombre']) == 0:
                errores['nombre'] = "Nombre es obligatorio"
            if len(postData['alias']) == 0:
                errores['alias'] = "Alias es obligatorio"
            EMAIL = re.compile(
                r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
            if not EMAIL.match(postData['email']):
                errores['email'] = "email invalido"
            if len(postData['password']) < 6:
                errores['password'] = "Password debe ser mayor a 6 caracteres"

            val_pass = self.comparar_password(postData['password'],postData['password2'])
            if len(val_pass) > 0:
                errores['password'] = val_pass

        return errores

    def encriptar(self, password):
        password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return password.decode('utf-8')

    def validar_login(self, password, usuario ):
        errores = {}
        if len(usuario) > 0:
            pw_hash = usuario[0].password

            if bcrypt.checkpw(password.encode(), pw_hash.encode()) is False:
                errores['pass_incorrecto'] = "password es incorrecto"
        else:
            errores['usuario_invalido'] = "Usuario no existe"
        return errores
    
    def comparar_password(self,password, password2):
        if password != password2:
            return "Password no son iguales"

    def recuperar_password(self, postData):
        errores = {}
        if len(User.objects.filter(email=postData['email'])) > 0:
            pass
        else:
            errores['email'] = "Email no existe"
        return errores
        

class User(models.Model):
    id = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=40)
    alias = models.CharField(max_length=40)
    email = models.CharField(max_length=40)
    password = models.CharField(max_length=255)
    #cumple = models.DateTimeField()
    rol = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    #historico = models.IntegerField(default=0)
    objects = UserManager()


class Autor(models.Model):
    id = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=40)


class Libro(models.Model):
    id = models.AutoField(primary_key=True)
    titulo = models.CharField(max_length=40)
    autor = models.ForeignKey(Autor, on_delete=CASCADE, related_name="libros")


class Review(models.Model):
    id = models.AutoField(primary_key=True)
    usuario = models.ForeignKey(User, on_delete=CASCADE, related_name="reviewer")
    contenido = models.TextField(default='')
    libro = models.ForeignKey(Libro, on_delete=CASCADE, related_name="librox")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    rating = models.IntegerField(default=0)