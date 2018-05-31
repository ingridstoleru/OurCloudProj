from django.urls import path
from django.conf.urls import url, include

from .home import HomeView
from .help import HelpView
from .login import LoginView
from .myaccount import MyAccountView
from .urlsp import MyURLsView
from .myscript import DoMyStuff
from .sentiment_analysis_script import DoSentimentAnalysis
from .github_retrieve import DoGithubRetrieve
from .vt import VIView
from .views import views as core_views

from django.contrib.auth import views as auth_views 

urlpatterns = [
    # ex: /polls/
    url(r'^', include( ('django.contrib.auth.urls', "auth"), namespace="auth")),
    #url(r'^', include( ('social.apps.django_app.urls', "social"), namespace="social")),
    url(r'^$', HomeView.as_view(template_name='home.html'), name='home'),
    url(r'^help', HelpView.as_view(template_name='help.html'), name='help'),
    url(r'^login_page', LoginView.as_view(template_name='login_2.html'), name='login_2'),
    url(r'^signup', core_views.signup, name='signup'),    
    url(r'^login/$', auth_views.login, name='login'),
    url(r'^logout/$', auth_views.logout, name='logout'),
    url(r'^mystuff/$', DoMyStuff.as_view(), name='mystuff'),
    url(r'^sentiment/$', DoSentimentAnalysis.as_view(), name='sentiment'),
    url(r'^github/$', DoGithubRetrieve.as_view(), name='github'),
    url(r'^myaccount', MyAccountView.as_view(template_name='myaccount.html'), name='myaccount'), 
    url(r'^urlsparse/$', MyURLsView.as_view(), name='urlsparse'), 
    url(r'^vt', VIView.as_view(), name='vt'), 
]