from django.shortcuts import render, redirect
from django.contrib import messages
from login.models import User, Autor, Libro, Review


# Create your views here.
def libros(request):
    if 'user_id' not in request.session:
        return redirect('login')
    
    context = {
        "active_user": User.objects.get(id=request.session['user_id']),
        "lista_libros": Libro.objects.all().order_by('id').reverse(),
        "lista_libros2": Libro.objects.all().order_by('titulo'),
    }

    return render(request, 'libros.html', context)

def agregar(request):
    context ={
        'autores': Autor.objects.all(),
    }
    return render(request, 'agregar.html', context)

def insertar(request):
    # Rescatando la info desde el Review
    # con variables errores, vamos a capturar errores
    errores = {}

    if int(request.POST['sautor']) == 0 and len(request.POST['autor']) == 0:
        errores['autor'] = "Debe seleccionar o crear un autor"  

    if len(request.POST['review']) == 0:
        errores['review'] = "Debe ingresar una reseña"

    if int(request.POST['rating']) == 0:
        errores['rating'] = "Debe seleccionar una calificación"

    if len(request.POST['titulo']) == 0:
        errores['titulo'] = "Debe ingresar un título"

    if len(errores) > 0:
        for key, msg in errores.items():
            messages.error(request, msg)
        return render(request, 'agregar.html')
    else:
        if int(request.POST['sautor']) != 0:
        # Si es distinto de 0, viene el autor y tendremos que ir a buscarlo
            autor = Autor.objects.get(id=request.POST['sautor'])    
        elif len(request.POST['autor']) != 0:
            autores = Autor.objects.all()
            registered_author = 0
            for autor_guardado in autores:
                if autor_guardado.nombre.lower() == request.POST['autor'].lower():
                    registered_author = autor_guardado.id
            if registered_author > 0:
                autor = Autor.objects.get(id=registered_author)
            else:
                autor = Autor.objects.create(nombre=request.POST['autor'].capitalize())
        book = Libro.objects.create(titulo = request.POST['titulo'], autor = autor )
        Review.objects.create(usuario = User.objects.get(id=request.session['user_id']), contenido = request.POST['review'], libro = book,rating = request.POST['rating'])
        return redirect('libros')

def recuperar(request):
    reg_user = User.objects.get(id=request.session['user_id'])

    context = {
        "active_user": reg_user,
    }
    return render(request, 'recuperar.html', context)

def cambiar_pass(request):
    reg_user = User.objects.get(id=request.session['user_id'])

    pass_actual = request.POST['pass_actual']
    pass_nueva = request.POST['pass_nueva']
    pass_confirm = request.POST['pass_confirmacion']

    context = {
        "active_user": reg_user,
    }
    return render(request, 'recuperar.html', context)


def edit(request, libro_id):
    context = {
        'libro': Libro.objects.get(id = libro_id),
        'reviews': Review.objects.filter(libro = Libro.objects.get(id = libro_id)).order_by('-id')[:3],
    }
    return render(request, 'libro.html', context)


def add_review(request):
    review = Review.objects.create(
        usuario = User.objects.get(id=request.session['user_id']),
        contenido = request.POST['review'],
        libro = Libro.objects.get(id = request.POST['libro_id']),
        rating = request.POST['rating']
    )
    return redirect(f"/libros/{request.POST['libro_id']}")
