from django.urls import path

from . import views

app_name = 'log_in'
urlpatterns = [
    path('index/', views.index, name='index'),
    path('admin/add', views.MyuserCreateView.as_view(), name='add_admin'),
    path('admin/update/<int:id>', views.MyuserUpdateView.as_view(), name='update_admin'),
    path('admin/delete', views.deleteadmin, name='delete_admin'),
    path('admin/profile', views.admin_profile, name='admin_profile'),
    path('admin/activities', views.activities_admin, name='activities_admin'),
    path('adminlist/', views.admin_users_list, name='admin_users_list'),
    path('adminlist/data', views.admin_users_list_data, name='admin_users_list_data'),
    path('user/add', views.UserCreate, name='add_user'),
    path('user/model', views.ModelTrain, name='model_train'),
    path('user/model/train', views.TrainingModel, name='training_model'),
    path('user/model/collect', views.CollectDataset, name='collectdataset'),
    path('user/update/<int:id>', views.UserUpdate, name='update_user'),
    path('user/delete', views.deleteuser, name='delete_user'),
    path('userlist/', views.users_list, name='users_list'),
    path('userlist/data', views.users_list_data, name='users_list_data'),
    path('log_out/', views.log_out, name='log_out'),
    path('password/change', views.password_change, name='password_change'),
    path('password/reset/', views.password_reset, name='password_reset'),
    path('password/reset/update/', views.password_reset_using_token, name='password_reset_using_token'),
    path('adminlog', views.LoginLogss, name='log_in'),
    path('user/home', views.UserLoginPageB, name='userloginpageb'),
    path('', views.UserLoginPageA, name='userloginpagea'),
]