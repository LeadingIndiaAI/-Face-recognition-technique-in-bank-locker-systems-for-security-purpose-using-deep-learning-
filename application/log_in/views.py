from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect, get_object_or_404
from .models import Myuser, LoginLogs, UserData
from .forms import MyuserForm, LoginLogsForm, UserDataForm, OtpVeriForm, UserLoginA, PasswordResetForm, PasswordResetWithTokenForm, PasswordChangeForm
from django.conf import settings
from django.views import generic
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseServerError, Http404
from django.urls import reverse
from django.contrib.auth import get_user_model
import random, string
from django.core.mail import send_mail
from django.http import JsonResponse
from django.core import signing
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMessage
from django.contrib.sessions.models import Session
from django.contrib.auth import update_session_auth_hash
from django.utils.timezone import utc
from django.db.models import Q

User = get_user_model()
import datetime
import time
def index(request):
    return render(request, 'log_in/index.html')

def LoginLogss(request):

    if  request.user.is_authenticated:
        return redirect('log_in:admin_profile')

    else:
        if request.method == 'POST':
            form = LoginLogsForm(request.POST)
            if form.is_valid():
                try:
                    user = authenticate(username=form.cleaned_data['email'], password=form.cleaned_data['password'])
                    if user:
                        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                        if x_forwarded_for:
                            ip = x_forwarded_for.split(',')[0]
                        else:
                            ip = request.META.get('REMOTE_ADDR')
                        ide = User.objects.get(id=user.id)
                        ide.password_reset_token = None
                        ide.save()
                        obj = LoginLogs.objects.filter(email=form.cleaned_data['email']).latest('id')

                        # print('----------------id----------------',obj.id)
                        if obj.login_time and not obj.logout_time:
                                messages.error(request, 'Already logged in,log out from there to continue.')
                                return redirect('log_in:log_in')
                        else:
                            raise LoginLogs.DoesNotExist
                    else:
                        messages.error(request, 'Invalid Email OR Password')
                        return redirect('log_in:log_in')

                except LoginLogs.DoesNotExist:
                    o = LoginLogs(ip_address=ip,
                                  user_id=ide,
                                  logintry_time=datetime.datetime.now().isoformat(),
                                  agent=request.META['HTTP_USER_AGENT'],
                                  email=form.cleaned_data['email'],
                                  password=make_password(form.cleaned_data['password']),
                                  otp_verified=1,
                                  login_time = datetime.datetime.now().isoformat(),
                                  otp=''.join(
                                      random.choice(
                                          string.ascii_uppercase + string.ascii_lowercase + string.digits)
                                      for i
                                      in range(6))

                                  )
                    o.save()
                    # check = LoginLogs.objects.get(id=request.session['user.id'], email=user.email, otp=user.otp)
                    # if check:
                    obj = LoginLogs.objects.filter(email=form.cleaned_data['email']).latest('id')
                    request.session['idid'] = obj.id
                    login(request, user)
                    return redirect('log_in:admin_profile')


                except Exception as e:
                    print("Excpeth ", e)
                    return HttpResponseServerError(
                        'Some error occured during saving the data. Please try later or contact your administrator.')
        else:
            form = LoginLogsForm()
        return render(request, 'log_in/log_in.html', {'form': form})

@login_required
def admin_profile(request):
    user = User.objects.get(id=request.user.id)
    all_activities = LoginLogs.objects.filter(user_id=user.id)
    return render(request, 'log_in/admin_users_profile.html', {'object': all_activities, 'id': user.id, 'username': user.username, 'email': user.email })

@login_required
#To view the lists of ADMINS
def admin_users_list(request):
    return render(request, 'log_in/admin_users_list.html',{'admin':request.user.email})


@login_required
def admin_users_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        queryset_and_total_count = admin_user_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password': user.password,
            'is_active': user.is_active,
            'date_joined': user.date_joined,
            'updated_on': user.updated_on,
            'created_by': user.created_by_id,
            'updated_by': user.updated_by_id,
            # 'filename': name.filename,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def admin_user_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    total_count = User.objects.all()
    queryset = User.objects.all()
    total_count = total_count.count()


    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(email__icontains=search)|Q(username__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}


class MyuserCreateView(generic.CreateView):
    # Add new Admin
    queryset = Myuser.objects.all()
    template_name = 'log_in/add_admin.html'
    context_object_name = 'form'
    form_class = MyuserForm

    def form_valid(self, form):
        try:
            self.object = form.save(commit=True)
            return HttpResponseRedirect(reverse('log_in:admin_users_list'))
        except Exception as e:
            print("Excpeth ", e)
            return HttpResponseServerError(
                'Some error occured during saving the data. Please try later or contact your administrator.')

    def get_form_kwargs(self):
        kwargs = super(MyuserCreateView, self).get_form_kwargs()
        kwargs.update({'logged_admin': self.request.user.id})
        return kwargs

class MyuserUpdateView(generic.UpdateView):
    #Update Admin
    model = Myuser
    queryset = Myuser.objects.all()
    form_class = MyuserForm
    pk_url_kwarg = 'id'
    template_name = 'log_in/update_admin_user.html'
    context_object_name = 'form'

    def form_valid(self, form):
        try:
            self.object = form.save(commit=True)
            update_session_auth_hash(self.request, self.object)
            return HttpResponseRedirect(reverse('log_in:admin_users_list'))
        except Exception as e:
            print("Excpeth ", e)
            return HttpResponseServerError(
                'Some error occured during saving the data. Please try later or contact your administrator.')

    def get_form_kwargs(self):
        kwargs = super(MyuserUpdateView, self).get_form_kwargs()
        kwargs.update({'logged_admin': self.request.user.id})
        return kwargs

@login_required
def deleteadmin(request):
    #To Delete the Admin
    user_id = request.GET.get('user_id', None)
    instance = User.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)

@login_required
def activities_admin(request):
    #View Activities of Admin
    #print("in view_logs_list")
    user_id = request.GET.get('user_id', None)
    #print(user_id)
    obj = User.objects.get(id=user_id)
    #check = LoginLogs.objects.get(email=request.user.email, user_id=user_id)
    all_activities = LoginLogs.objects.filter(user_id=user_id)
    # print(check.email,check.id)
    # #print(check)
    return render(request, 'log_in/view_logs_list.html', {'object': all_activities, 'email' : obj.email})

@login_required
def password_change(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            oldpassword = form.cleaned_data['old_password']
            newpassword = form.cleaned_data['new_password']
            renewpassword = form.cleaned_data['retype_newpassword']
            if not request.user.check_password(oldpassword):
                messages.error(request, 'Enter correct Old Password.')
                return redirect('log_in:password_change')
            else:
                if newpassword != renewpassword:
                    messages.error(request, 'Both New Password and Retype New Password should match. ')
                    return redirect('log_in:password_change')
                else:
                    idid = request.session['idid']
                    request.user.password = make_password(newpassword)
                    print(request.user.password)
                    request.user.save()
                    email=request.user.email
                    logout(request)
                    print(email)
                    try :
                        user = authenticate(username=email, password=newpassword)
                        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                        request.session['idid'] = idid
                        messages.error(request, 'Password Successfully changed ')
                        return redirect('log_in:password_change')
                    except Exception as e:
                        print("Excpeth ", e)
                        return HttpResponseServerError('Some error occured during saving the data. Please try later or contact your administrator.')
        else:
            print("Form ", form.errors)
    else:
        form = PasswordChangeForm()
    return render(request, 'log_in/change_password.html', {'form': form})

#forgot_password
def password_reset(request):
    form = PasswordResetForm()
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email_id = form.cleaned_data['email']
            if email_id:
                try:
                    user = get_user_model().objects.get(email=email_id)

                    obj = LoginLogs.objects.filter(email=user.email).latest('id')
                    print('-------------------id---------------', user.email, obj.logout_time, '====', (obj.login_time),
                          '====', (obj.id))
                    if not obj.logout_time and (obj.login_time):
                        obj.logout_time = datetime.datetime.now().isoformat()
                        obj.save()

                    raise LoginLogs.DoesNotExist
                except LoginLogs.DoesNotExist:
                    user = get_user_model().objects.get(email=email_id)
                    reset_token = get_token()
                    user.password_reset_token = reset_token
                    user.save()
                    encrypted_data = signing.dumps({'email': email_id, 'token': reset_token})
                    reset_url = settings.BASE_URL + 'log_in/password/reset/update/?token=' + encrypted_data
                    content = "<p>Please click the link below to reset your password<p>"
                    content += "<a href='" + reset_url + "'>" + reset_url + "</a>"
                    subject = 'Reset password'
                    to = email_id
                    from_mail = settings.EMAIL_HOST_USER
                    mail = EmailMessage(subject=subject, body=content, to=(to,), from_email=from_mail)
                    mail.content_subtype = 'html'
                    mail.send()
                    messages.success(request, 'We have successfully send a password reset link to your email ID.')
                    return HttpResponseRedirect(reverse('log_in:log_in'))

                except Exception as e:
                    messages.error(request, 'It seems that you have entered invalid email id.', extra_tags='danger')
                    return HttpResponseRedirect(reverse('log_in:log_in'))
            else:
                msg = 'Please enter the valid credentials.'
                return render(request, 'log_in/reset_password.html', {'form': form, 'error_msg': msg})
        else:
            return render(request, 'log_in/reset_password.html', {'form': form})
    else:
        return render(request, 'log_in/reset_password.html', {'form': form})


def get_token():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in
            range(50))


def password_reset_using_token(request):
    if request.method == 'POST':
        token = request.POST.get("token")
        form = PasswordResetWithTokenForm(request.POST)
        if form.is_valid():
            try:
                print("in 2nd try")
                print('------',settings.BASE_URL +'log_in/password/reset/update/?token='+token)
                newpassword = form.cleaned_data['new_password']
                renewpassword = form.cleaned_data['retype_newpassword']
                decrypted_data = signing.loads(token)
                user_obj = get_user_model().objects.get(password_reset_token=decrypted_data['token'],email=decrypted_data['email'])
                if newpassword != renewpassword:
                    messages.error(request, 'Both New Password and Retype New Password should match. ')
                    return HttpResponseRedirect(settings.BASE_URL + 'log_in/password/reset/update/?token=' + token)
                else:
                    user_obj.password = make_password(newpassword)
                    user_obj.password_reset_token = None
                    user_obj.save()
                    messages.success(request, 'Your password has been successfully changed, Please login to check it.')
                    return HttpResponseRedirect(reverse('log_in:log_in'))

            except Exception as e:
                messages.error(request, 'Link expired,try again.')
                return HttpResponseRedirect(reverse('log_in:log_in'))

    else:
        token = request.GET.get('token', None)
        decrypted_data = signing.loads(token)
        decrypted_token = decrypted_data['token']
        decrypted_email = decrypted_data['email']
        #print('----------------decryptedtoken--------------',decrypted_token)
        obj = User.objects.get(email = decrypted_email)
        #print('----------------token--------------', obj.password_reset_token)
        if (decrypted_token != obj.password_reset_token) or token is  None:
            messages.error(request, 'Link expired,try again.')
            return HttpResponseRedirect(reverse('log_in:log_in'))
        else:
            form = PasswordResetWithTokenForm()
    return render(request, 'log_in/reset_password_with_token.html', {'form': form,'token':token})

#Now functions for Users
@login_required
#To view the lists of USERS
def users_list(request):
    return render(request, 'log_in/users_list.html',{'admin':request.user.email})


@login_required
def users_list_data(request):
    if request.method == 'GET':
        draw = int(request.GET.get('draw', 1))
        obj = UserData.objects.all()
        queryset_and_total_count = user_get_queryset_and_count(request)
        total_count = queryset_and_total_count.get('total_count')
        queryset = queryset_and_total_count.get('queryset')
        response_data = [{
            'id': user.id,
            'lockerno': user.lockerno,
            'username': user.username,
            'foldername': user.foldername,
        } for user in queryset]
        return JsonResponse(
            {'draw': draw, 'recordsTotal': total_count, 'recordsFiltered': total_count, 'data': response_data})
    else:
        return JsonResponse({})

def user_get_queryset_and_count(request):
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    total_count = UserData.objects.all()
    queryset = UserData.objects.all()
    total_count = total_count.count()


    order_column = request.GET.get('order[0][column]', None)
    if order_column == None:
        arguments='id'
    else:
        field = request.GET.get('columns['+order_column+'][data]', None)
        order = request.GET.get('order[0][dir]', None)
        if order == 'asc':
            arguments = field
        else:
            arguments = "-" + field


    search = request.GET.get('search[value]', None)
    if search:
        queryset = queryset.order_by(arguments).filter(Q(lockerno__icontains=search)|Q(username__icontains=search))[start:length + start]
    else:
        queryset = queryset.order_by(arguments)[start:length + start]
    return {'queryset': queryset, 'total_count': total_count}

@login_required
def UserCreate(request):
    if request.method == 'POST':
        form = UserDataForm(request.POST, request.FILES)
        if form.is_valid():

            o = UserData(lockerno = form.cleaned_data['lockerno'], username = form.cleaned_data['username'],
                         foldername="Folder")
            o.save()
            request.session['lockerno'] = form.cleaned_data['lockerno']
            return HttpResponseRedirect(reverse('log_in:model_train'))
        else:
            print("Form ", form.errors)
    else:
        form = UserDataForm()
    return render(request, 'log_in/add_user.html', {'form': form})

@login_required
def ModelTrain(request):
    return render(request, 'log_in/dataset_and_training_of_model.html')

import cv2
import time
import os
import shutil
import subprocess
import shlex
import signal
@login_required
def CollectDataset(request):
    lockernumber = request.session['lockerno']
    userobject = UserData.objects.get(lockerno=lockernumber)
    foldername=str(userobject.lockerno)+str(userobject.username)
    # Create a VideoCapture object
    cap = cv2.VideoCapture(0)
    # Check if camera opened successfully
    if (cap.isOpened() == False):
        print("Unable to read camera feed")
    capture_duration = 35
    # We convert the resolutions from float to integer.
    frame_width = int(cap.get(3))
    frame_height = int(cap.get(4))
    newpath = r'database/images/'+foldername
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    # Define the codec and create VideoWriter object.The output is stored in 'outpy.avi' file.
    out = cv2.VideoWriter('database/images/'+foldername+'/video.mp4', cv2.VideoWriter_fourcc('M', 'J', 'P', 'G'), 10, (frame_width, frame_height))
    start_time = time.time()
    while (int(time.time() - start_time) < capture_duration):
        ret, frame = cap.read()
        frame = cv2.flip(frame, 1)
        if ret == True:
            # Write the frame into the file 'output.avi'
            out.write(frame)
            # Display the resulting frame
            cv2.imshow('frame', frame)
            # Press Q on keyboard to stop recording
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        # Break the loop
        else:
            break
        # When everything done, release the video capture and video write objects
    cap.release()
    out.release()
    # Closes all the frames
    cv2.destroyAllWindows()

    newpath = r'database/images/' + foldername + '/frames/'+userobject.username
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    vidcap = cv2.VideoCapture('database/images/'+foldername+'/video.mp4')
    count = 0
    success = True
    while success:
        success, image = vidcap.read()
        print('Read a new frame: ', success)
        cv2.imwrite("database/images/"+foldername+"/frames/"+userobject.username+"/frame%d.jpg" % count, image)  # save frame as JPEG file
        count += 1
    os.remove("database/images/"+foldername+"/frames/"+userobject.username+"/frame"+str(count-1)+".jpg")
    os.remove("database/images/" + foldername +"/video.mp4")
    shutil.copytree("database/images/00not", "database/images/" + foldername + "/frames/00not")
    os.rename("database/images/" + foldername + "/frames/00not", "database/images/" + foldername + "/frames/not"+userobject.username)

    userobject.foldername = "database/images/"+foldername
    userobject.save()
    return redirect('log_in:model_train')

def TrainingModel(request):
    lockernumber = request.session['lockerno']
    userobject = UserData.objects.get(lockerno=lockernumber)
    foldername = str(userobject.lockerno) + str(userobject.username)

    #path = "database/videosplitter.py"
    #exec(open(path).read())
    print('============pathhh==============')
    os.chdir("/home/tanuj/Probennett/application/database/")
    os.system('python -m retrain --output_graph=images/'+foldername+'/retrained_graph.pb --output_labels=images/'+foldername+'/retrained_labels.txt --architecture=inception_v3 --image_dir=images/'+foldername+'/frames')
    os.chdir("/home/tanuj/Probennett/application/")

    #python -m retrain --output_graph=images/7kartik/retrained_graph.pb --output_labels=images/7kartik/retrained_labels.txt --architecture=inception_v3 --image_dir=images/7kartik/frames/


    #path = "database/retrain.py"
    #exec(open(path).read(),"--output_graph=database/images/"+foldername+"/retrained_graph.pb --output_labels=database/images/"+foldername+"/retrained_labels.txt --architecture=inception_v3 --image_dir=database/images/"+foldername+"/frames")
    #exec(open(path).read(),
    #cmd=[path,"--output_graph=database/images/" + foldername + "/retrained_graph.pb"," --output_labels=database/images/" + foldername + "/retrained_labels.txt"," --architecture=inception_v3"," --image_dir=database/images/" + foldername + "/frames"]
    #subprocess.call(cmd,shell=True)
    #subprocess.call(shlex.split(cmd), shell=False)
    #pro = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    #os.killpg(os.getpgid(pro.pid), signal.SIGTERM)

    shutil.rmtree("database/images/" + foldername + "/frames/not"+userobject.username)
    return redirect('log_in:model_train')


@login_required
def UserUpdate(request,id):
    if request.method == 'POST':
        form = UserDataForm(request.POST, request.FILES)
        up = get_object_or_404(UserData, pk=id)
        if form.is_valid():
            up.lockerno = form.cleaned_data['lockerno']
            up.username = form.cleaned_data['username']
            up.save()
            return redirect('log_in:users_list')

    else:
        up = get_object_or_404(UserData, pk=id)
        form = UserDataForm(request.POST or None,instance=up)
    print("=============id===========",id)
    return render(request, 'log_in/update_user.html', {'form': form, 'id' : id})

@login_required
def deleteuser(request):
    #To Delete the user
    user_id = request.GET.get('user_id', None)
    instance = UserData.objects.get(pk=int(user_id))
    instance.delete()
    data = {'qwe': 'asd'}
    return JsonResponse(data)

import argparse
import time
import sys
import numpy as np
import tensorflow as tf
from cv2 import *


def load_graph(model_file):
    graph = tf.Graph()
    graph_def = tf.GraphDef()

    with open(model_file, "rb") as f:
        graph_def.ParseFromString(f.read())
    with graph.as_default():
        tf.import_graph_def(graph_def)

    return graph


def capture_image():
    cam = cv2.VideoCapture(0)
    s, img = cam.read()
    img = cv2.flip(img,1)
    if s:
        cv2.namedWindow("Taking Image...")
        cv2.imshow("Taking Image...", img)
        cv2.waitKey(0)
        cv2.imwrite("/tmp/image.jpg", img)
        cv2.destroyAllWindows()


def read_tensor_from_image_file(file_name, input_height=299, input_width=299,
                                input_mean=0, input_std=255):
    input_name = "file_reader"
    output_name = "normalized"
    file_reader = tf.read_file(file_name, input_name)
    if file_name.endswith(".png"):
        image_reader = tf.image.decode_png(file_reader, channels=3,
                                           name='png_reader')
    elif file_name.endswith(".gif"):
        image_reader = tf.squeeze(tf.image.decode_gif(file_reader,
                                                      name='gif_reader'))
    elif file_name.endswith(".bmp"):
        image_reader = tf.image.decode_bmp(file_reader, name='bmp_reader')
    else:
        image_reader = tf.image.decode_jpeg(file_reader, channels=3,
                                            name='jpeg_reader')
    float_caster = tf.cast(image_reader, tf.float32)
    dims_expander = tf.expand_dims(float_caster, 0);
    resized = tf.image.resize_bilinear(dims_expander, [input_height, input_width])
    normalized = tf.divide(tf.subtract(resized, [input_mean]), [input_std])
    sess = tf.Session()
    result = sess.run(normalized)

    return result


def load_labels(label_file):
    label = []
    proto_as_ascii_lines = tf.gfile.GFile(label_file).readlines()
    for l in proto_as_ascii_lines:
        label.append(l.rstrip())
    return label

def UserLoginPageA(request):
    if request.method == 'POST':
        form = UserLoginA(request.POST)
        if form.is_valid():
            try:
                obj = UserData.objects.get(lockerno=form.cleaned_data['lockerno'])
                request.session['lockerno'] = form.cleaned_data['lockerno']
                foldername = str(obj.lockerno) + str(obj.username)
                temp = 0
                if obj:
                    print(obj.username)
                    capture_image()
                    file_name = "/tmp/image.jpg"
                    model_file = "/home/tanuj/Probennett/application/database/images/" + foldername + "/retrained_graph.pb"
                    label_file = "/home/tanuj/Probennett/application/database/images/" + foldername + "/retrained_labels.txt"
                    input_height = 299
                    input_width = 299
                    input_mean = 0
                    input_std = 255
                    input_layer = 'Mul'
                    output_layer = "final_result"
                    print('===================================================')
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--image", help="image to be processed")
                    parser.add_argument("--graph", help="graph/model to be executed")
                    parser.add_argument("--labels", help="name of file containing labels")
                    parser.add_argument("--input_height", type=int, help="input height")
                    parser.add_argument("--input_width", type=int, help="input width")
                    parser.add_argument("--input_mean", type=int, help="input mean")
                    parser.add_argument("--input_std", type=int, help="input std")
                    parser.add_argument("--input_layer", help="name of input layer")
                    parser.add_argument("--output_layer", help="name of output layer")

                    graph = load_graph(model_file)
                    t = read_tensor_from_image_file(file_name,
                                                    input_height=input_height,
                                                    input_width=input_width,
                                                    input_mean=input_mean,
                                                    input_std=input_std)

                    input_name = "import/" + input_layer
                    output_name = "import/" + output_layer
                    input_operation = graph.get_operation_by_name(input_name);
                    output_operation = graph.get_operation_by_name(output_name);

                    with tf.Session(graph=graph) as sess:
                        start = time.time()
                        results = sess.run(output_operation.outputs[0],
                                           {input_operation.outputs[0]: t})
                        end = time.time()
                    results = np.squeeze(results)

                    top_k = results.argsort()[-5:][::-1]
                    labels = load_labels(label_file)

                    ##print('\nEvaluation time (1-image): {:.3f}s\n'.format(end-start))

                    i = results[1]
                    i *= 100
                    if i >= 75:
                        print('Recognised as')
                        print(labels[1], results[1])
                        temp=1
                    else:
                        print('Not Recognised!',i)
            
                    if (temp == 1):
                        return redirect('log_in:userloginpageb')
                    else:
                        messages.error(request, 'Invalid Face.')
                        return redirect('log_in:userloginpagea')
            except UserData.DoesNotExist:
                messages.error(request, 'Invalid Locker Number')
                return redirect('log_in:userloginpagea')
            except Exception as e:
                print("Excpeth====================", e)
                messages.error(request, 'Some error occured during saving the data. Please try later or contact your administrator.')
                return redirect('log_in:userloginpagea')
        else:
            print("Form ", form.errors)

    else:
        form = UserLoginA()
    return render(request, 'log_in/user_log_in.html', {'form': form})




def UserLoginPageB(request):
    print("CODE TO MATCH THE FACE")
    lockerno = request.session['lockerno']
    obj = UserData.objects.get(lockerno=lockerno)
    return render(request, 'log_in/welcome_user.html', {'name': obj.username})

@login_required
def log_out(request):
    var = request.session['idid']
    print("======",var)
    o2 = LoginLogs.objects.get(id=var)
    o2.logout_time = datetime.datetime.now().isoformat()
    o2.save()
    logout(request)
    messages.success(request, 'Sucsessfully logged out.')
    return redirect('log_in:log_in')
