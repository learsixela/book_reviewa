from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from time import gmtime, strftime
from django.db.models import Count
import bcrypt

from .models import *

# Create your views here.
def login(request):
    if 'user_id' in request.session:
        return redirect('libros/')
    return render(request, 'registro.html')


def registrar(request):
    return render(request, 'registro.html')


def inicio(request):
    usuario = User.objects.filter(email=request.POST['email2'].lower())
    errores = User.objects.validar_login(request.POST['password'], usuario)

    if len(errores) > 0:
        for key, msg in errores.items():
            messages.error(request, msg)
        return redirect('/')
    else:
        request.session['user_id'] = usuario[0].id
        request.session['user_name'] = usuario[0].nombre
        return redirect('libros/')


def registro(request):
    #validacion de parametros
    errors = User.objects.basic_validator(request.POST)

    if len(errors) > 0:
        for key, msg in errors.items():
            messages.error(request, msg)
        return redirect('/registrar')

    else:
        #encriptar password
        password = User.objects.encriptar(request.POST['password'])
        
        rol = 2
        if User.objects.all().count() == 0:
            rol = 1

        #crear usuario
        user = User.objects.create(
            nombre=request.POST['nombre'],
            alias=request.POST['alias'],
            email=request.POST['email'],
            password=password,
            rol=rol,
        )
        #request.session['user_id'] = user.id
        #retornar mensaje de creacion correcta
        msg="Usuario creado exitosamente!"
        messages.success(request, msg)
    return redirect('/')


def logout(request):
    request.session.flush()
    return redirect('/')


def view_user(request, user_id):
    usuario = User.objects.get(id = user_id)
    dict_review = Review.objects.filter(usuario = usuario).values('libro').annotate(total=Count('libro'))
    arreglo_libros = []
    for rev in dict_review:
        arreglo_libros.append(
            Libro.objects.filter(id = rev['libro'])
        )
    context = {
        'user': usuario,
        'rev_count': Review.objects.filter(usuario = usuario).count(),
        'reviews': arreglo_libros,
            }
    return render(request, 'user.html', context)


def cambiar_pass(request):
    reg_user = User.objects.filter(id=request.session['user_id'])
    errores = User.objects.validar_login(request.POST['pass_actual'], reg_user)
    
    if len(errores) > 0:
        for key, msg in errores.items():
            messages.error(request, msg)
        return render(request, 'recuperar.html')
    else:
        pass_nueva = request.POST['pass_nueva']
        pass_confirm = request.POST['pass_confirmacion']
        if len(pass_nueva) < 6:
            messages.error(request, "nuevo password debe ser mayor o igual a 6 caracteres", extra_tags='pass_nueva')
            return render(request, 'recuperar.html')

        mensaje = User.objects.comparar_password(pass_nueva,pass_confirm)
        print(mensaje)
        if len(mensaje) > 0:
            messages.error(request, mensaje)
            return render(request, 'recuperar.html')
        
        password_encriptado = User.objects.encriptar(pass_nueva)

        reg_user[0].password = password_encriptado
        reg_user[0].save()
        request.session.flush()
        return redirect('/')