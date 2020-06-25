# django_register_with_email_confirm
Inscription avec activation du compte après confirmation du mail


### créer un fichier token.py dans notre application qui gère la connexion et l'inscription
##### contenu de token.py

```python
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.is_active)
        )
account_activation_token = TokenGenerator()
```



### in views.py

```python

### in views.py #####
from django.shortcuts import render,redirect

from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.contrib.auth import authenticate,login,logout
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from . import token as token_
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode

# Create your views here.

####### Fonction de recuperation et de traitement des données en cas de post ###############
def inscription(request):
    message = ""
    if request.method == 'POST':
    
        ##### récupération des données (les valeurs entre parenthèses correspondent au name de nom input dans le html #######"
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        username = request.POST.get('name')
        email = request.POST.get('email')
        genre = request.POST.get('genre')
        passe = request.POST.get('pass')
        repass = request.POST.get('repass')
        
        #### vérification de la conformité des mots de passe
        if passe != repass:
            message = "mot de passe incorrect "
            print("mot de passe incorrect")
        else:
            message = "correct"
            print("success")
            try:
                
                print("3")
                validate_email(email)#### vérifer que le mail est correct
                isemail = True
                if  isemail and not email.isspace() and first_name is not None and not first_name.isspace() and last_name is not None and passe is not None and repass is not None:
                    try:
                        #### vérifier si un utilisateur avec le meme username ou email n'existe pas
                        print("2")
                        try:
                            exist_user = User.objects.get(username=username)
                        except :
                            exist_user = User.objects.get(email=email)

                        message = "un utilisateur avec le même username ..."
                    except Exception as e :
                        #### création de notre nouvel utilisateur
                        print("1", e)
                        user = User(
                            first_name=first_name,
                            last_name=last_name,
                            username=username,
                            email=email,
                            is_active = False
                        )
                        user.save() 
                        
                        ### enregistrment du password
                        user.password = passe
                        user.set_password(user.password)
                        user.save()
                        
                        ####### debut de l'envoie de mail de confirmation
                        current_site = get_current_site(request)
                        subject = 'Activate Your MySite Account'
                        message = render_to_string('account_activation_email.html', {
                            'user': user,
                            'domain': current_site.domain,
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                            'token': token_.account_activation_token.make_token(user),
                        })
                        
                        ### envoie du mail
                        ### NB il faut spécifier l'email_backend dans le settings
                        ### ici on utilisera EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' (a mettre dans settings.py)
                        send_mail(
                                mail_subject,
                                message,
                                'marylise@gmail.com',
                                [user.email],
                        ) 
                        
                        message = " merci de vérifier votre email pour la confirmation de votre compte"
                
            except Exception as e:
                print("5", e)
                message = "l'inscription a échoué"
                print("inscription echoué")


    datas = { 
            "message":message,
    }
    return render(request,"inscription.html",datas)


###### connexion de l'utilisateur
def connexion(request):
    message = ""
    if request.method == 'POST':
        name = request.POST.get("name")
        password = request.POST.get("pass")
        user = authenticate(username=name,password=password)
        if user is not None and user.is_active:
            login(request,user)
            
            #### redirection si les infos sont correctes
            return redirect('index')
        else:
            print("login échoué")
            message = "Merci de vérifiez vos informations"

    datas = {
      'message': message
    }
    return render(request,"login.html",datas)


##### déconnexion
def is_deconnexion(request):
    logout(request)
    return redirect('login')



##### activation du mail
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and token_.account_activation_token.check_token(user, token):
        user.is_active = True
        user.profile.email_confirmed = True
        user.save()
        login(request, user)
        return redirect('index')
    else:
        return render(request, 'invalide_token.html')
        
```


#### dans le fichier urls.py 
```python

path('account_confirm/<slug:uidb64>/<slug:token>/',views.activate,name="account_confirm_email"),#### route de confirmation du mail

```

##### Dans votre dossier templates créer le fichier account_activation_email.html

```html
  
{% autoescape off %} Hi {{ user.username }}, Please click on the link to confirm
your registration, {{ domain }}{% url 'account_confirm_email' uidb64=uid token=token %}
{% endautoescape %}

```
