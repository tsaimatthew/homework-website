from django.shortcuts import render
from django.http import HttpResponse
from django.http.response import JsonResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required, user_passes_test
import os
from .models import IcsHashVal, NotionData, SchoologyClasses, SchoologyAuth, IntegrationLog, Log, GradescopeClasses, GradescopeCredentials
import datetime
import json
import pytz
import requests
from .helper import notion_push, notion_expired, g_headers
import secrets
from time import time
import csv
from bs4 import BeautifulSoup


#import hwapp models
from hwapp.models import Homework, Class, Preferences, User
from mywebsite.settings import DEBUG

def superuser(user):
    return user.is_superuser
def user_in_group(*group_names):
    """Requires user membership in at least one of the groups passed in."""
    def in_groups(u):
        if u.is_authenticated:
            if bool(u.groups.filter(name__in=group_names)) | u.is_superuser:
                return True
        return False
    return user_passes_test(in_groups, login_url='403')
"""
LOGIN REQUIRED
"""
@login_required(login_url='/login')
def index(request):
    try:
        integrations = SchoologyAuth.objects.filter(h_user = request.user)
    except:
        integrations = False
    try:
        n_data = NotionData.objects.filter(notion_user=request.user)
    except:
        n_data = False
    try:
        n = n_data.get(tag="homework") # type: ignore
    except:
        n = False
    return render(request, 'hwapp/integrations.html', {
        'integrations': integrations,
        'n_datas': n_data,
        'int_status': n,
        'DEBUG': DEBUG,
        'domain_name': os.environ.get("DOMAIN_NAME")
    })  

@login_required(login_url='/login')
def notion_auth(request):
    try:
        n = NotionData.objects.get(notion_user=request.user, tag="homework")
    except:
        n = False
    return render(request, 'hwapp/notion_import.html', {
            'DEBUG': DEBUG,
            'int_status': n
    })

@login_required(login_url='/login')
def notion_callback(request):
    if request.method == "GET":
        if request.GET.get('code'):
            code = request.GET.get('code')
        elif request.GET.get('error'):
            return render(request, 'hwapp/error.html', {
                'error': request.GET.get('error')
            })
        else:
            return JsonResponse({"status": "400", "error": "no callback code"}, status=400)
        url = 'https://api.notion.com/v1/oauth/token'
        uri = {
            "dev": "http://localhost:8000/integrations/notion_callback",
            "prod": f"https://{os.environ.get('website_root')}/integrations/notion_callback",
        }
        redirect_uri = uri['dev' if DEBUG else 'prod']

        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }
        #b64 encode:
        import base64
        secret = f"{os.environ.get('notion_client_id')}:{os.environ.get('notion_secret')}".encode('utf-8')
        b64 = base64.b64encode(secret).decode('utf-8')

        response = requests.post(url, data=body, headers={"Authorization": f"Basic {b64}"})
        data1 = json.loads(response.text)
        # check if notion object exists and create if dne
        try:
            n_data = NotionData.objects.get(notion_user=request.user, tag="homework")
        except NotionData.DoesNotExist:
            n_data = NotionData.objects.create(notion_user=request.user)

        # check expiration and have user reauthorize notion if needed
        if str(response) != "<Response [200]>":
            notion_expired(request.user, n_data)
        
        # set attributes 
        n_data.notion_user = request.user
        n_data.access_token = data1['access_token']
        n_data.bot_id = data1['bot_id']
        n_data.workspace_name = data1['workspace_name']
        n_data.workspace_id = data1['workspace_id']
        n_data.tag = "homework"
        n_data.error = False
        n_data.save()
    #update notion personal if it exists:
        try:
            n_personal = NotionData.objects.get(notion_user=request.user, tag="personal")
            n_personal.access_token = data1['access_token']
            n_data.bot_id = data1['bot_id']
            n_personal.save()
        except NotionData.DoesNotExist:
            # not all users have a personal notion
            pass

        #get DB id (duplicated_template_id)
        try:
            #decode JSON
            data = 0
            try:
                data = json.loads(response.text)
                try:
                    db_id = data["results"][0]["id"]
                except (KeyError, IndexError):
                    db_id = data["results"][0].get("duplicated_template_id")
            except (json.JSONDecodeError, KeyError, IndexError):
                db_id = None
            url = 'https://api.notion.com/v1/databases'
            response = requests.get(url, headers={"Authorization": f"Bearer {n_data.access_token}", "Notion-Version": "2021-08-16"})
            n_data.db_id = db_id
            n_data.save()
        except:
            return render(request, 'hwapp/error.html', {
                'error': "Too many pages selected. Please return to the <a href=/integrations/notion_auth>previous page</a> and select only <b>ONE</b> page"
            })

        #get DB properties:
        url = f'https://api.notion.com/v1/databases/{n_data.db_id}'
        token = n_data.access_token
        page_id = n_data.db_id
        url = 'https://api.notion.com/v1/pages'
        to_post = Homework.objects.filter(hw_user=request.user, completed=False, notion_migrated=False)
        for hw in to_post:
            hw.due_date = datetime.datetime.strftime(hw.due_date, '%Y-%m-%dT%H:%M') # type: ignore
            body = {
                "parent": {
                    "database_id": f"{page_id}"
                },
                "properties": {
                    "Name": {
                        "title": [{
                                "text": {
                                    "content":f"{hw.hw_title}"
                                }}]
                        
                    },
                    "Status": {
                        "status": {
                            "name":"Not started"
                        }
                    },
                    "Class": {
                        "type": f"select",
                        "select": {
                            "name": f"{hw.hw_class.class_name}" # type: ignore
                        }
                    },
                    "Due": {
                        "type": "date",
                        "date": {
                            "start": f"{hw.due_date}",
                            "end": None,
                            "time_zone": "US/Pacific"
                        }
                    }
                    
                }
            }
            response = requests.post(url, data=json.dumps(body), headers={'Authorization': f'Bearer {token}', 'Notion-Version': '2022-06-28', "Content-Type": "application/json"})
            hw.notion_migrated = True
            hw.notion_id = json.loads(response.text)['id']
            hw.save()
        return render(request, 'hwapp/success.html', {
            'message': 'Notion feed integrated successfully'
        })
    else:
        return JsonResponse({"error": "invalid request"}, status=400)

@login_required(login_url='/login')
def schoology_class(request):
    try:
        s = SchoologyAuth.objects.get(h_user= request.user, src='Schoology')
    except:
        return render(request, 'hwapp/error.html', {
            'error': 'No Schoology Classes found. Please contact website admin for access'
        })
    url = f'https://api.schoology.com/v1/users/{s.user_id}/sections'
    headers = {
        "Authorization": f'OAuth realm="Schoology API",oauth_consumer_key="{s.s_consumer_key}",oauth_token="",oauth_nonce="{secrets.token_urlsafe()}",oauth_timestamp="{int(time())}",oauth_signature_method="PLAINTEXT",oauth_version="1.0",oauth_signature="{s.s_secret_key}%26"'
    }
    response = requests.get(url, headers=headers)
    response = json.loads(response.text)
    s_class = SchoologyClasses.objects.filter(schoology_user=request.user, src='Schoology')
    classes = []
    for i in s_class:
        classes.append(i.class_id)
    for i in response['section']:
        if i['id'] in classes:
            pass
        else:
            c = Class.objects.create(class_user=request.user, class_name=i['course_title'], external_src="Schoology", external_id=i['id'])
            SchoologyClasses.objects.create(
                schoology_user=request.user, 
                class_id=i['id'], 
                s_class_name=i['course_title'],
                s_grading_period=i['grading_periods'][0],
                linked_class=c, 
                src='Schoology', 
                auth_data=s
            )
    Log.objects.create(
        user=request.user, 
        date=datetime.datetime.now(), 
        message="Refreshed Schoology Classes", 
        error=False, 
        log_type="Schoology Refresh", 
        ip_address = request.META.get("REMOTE_ADDR")
    )
    return JsonResponse({"message": "Schoology class refreshed successfully"})
    
@login_required(login_url='/login')
def schoology_hw(request):
    try:
        c = SchoologyClasses.objects.filter(schoology_user=request.user, src='Schoology').exclude(update=False)
    except:
        return render(request, 'hwapp/error.html', {
            'error': 'No Schoology Classes found. Please contact website admin for access'
        })
    existing_hws = Homework.objects.filter(hw_user=request.user, external_src="Schoology")
    z = []
    for existing_hw in existing_hws:
        z.append(str(existing_hw.external_id))
    for class1 in c:
        s = class1.auth_data
        url = f"https://api.schoology.com/v1/sections/{class1.class_id}/assignments?start=0&limit=1000"
        headers = {
            "Authorization": (
                'OAuth realm="Schoology API",'
                f'oauth_consumer_key="{s.s_consumer_key}",' # type: ignore
                'oauth_token="",'
                f'oauth_nonce="{secrets.token_urlsafe()}",'
                f'oauth_timestamp="{int(time())}",'
                f'oauth_signature_method="PLAINTEXT",'
                f'oauth_version="1.0",'
                f'oauth_signature="{s.s_secret_key}%26"' # type: ignore
            )
        }   
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        if str(response) != "<Response [200]>":
            error = True
        else:
            error = False
        for hw in data['assignment']:
            if str(hw['id']) not in z:
                try:
                    l = datetime.datetime.strptime(hw['due'], "%Y-%m-%d %H:%M:%S")
                except:
                    l = datetime.datetime.now()
                h = Homework.objects.create(
                    hw_user=request.user,
                    hw_class=class1.linked_class,
                    hw_title=hw['title'],
                    external_id=hw['id'],
                    external_src="Schoology",
                    due_date=l,
                    notes=f"{hw['description']}, {hw['web_url']}",
                    completed=False,
                    overdue=False
                )
                IntegrationLog.objects.create(user=class1.schoology_user, src="schoology", dest="hwapp", url = url, date = datetime.datetime.now(), message=response.text, error=error, hw_name=h.hw_title)
                try:
                    notion_push(hw=h,user=request.user)
                except:
                    pass
            pass
    Log.objects.create(user=request.user, date=datetime.datetime.now(), message="Refreshed Schoology Homework", error=False, log_type="Schoology Refresh", ip_address = request.META.get("REMOTE_ADDR"))
    return JsonResponse({"message": "Schoology homework refreshed successfully"})

@login_required(login_url='/login')
def canvas_class(request):
    try:
        all = SchoologyAuth.objects.filter(h_user= request.user, src='Canvas')
    except:
        return render(request, 'hwapp/error.html', {
            'error': 'No Canvas Classes found. Please contact website admin for access'
        })

    for s in all:
        url = f'https://canvas.instructure.com/api/v1/courses?access_token={s.s_secret_key}&per_page=256'
        headers = {
            "Authorization": f'Bearer {s.s_secret_key}'
        }
        response = requests.get(url, headers=headers)
        response = json.loads(response.text)
        s_class = SchoologyClasses.objects.filter(schoology_user=request.user, src='Canvas')
        classes = []
        for i in s_class:
            classes.append(str(i.class_id))
        for i in response:
            try:
                assert i['access_restricted_by_date'] == True
            except KeyError:
                if str(i['id']) not in classes:
                    c = Class.objects.create(class_user=request.user, class_name=i['name'], external_src="Canvas", external_id=i['id'])
                    SchoologyClasses.objects.create(
                        schoology_user=request.user, 
                        class_id=i['id'],
                        s_class_name=i['name'],
                        s_grading_period=i['enrollment_term_id'],
                        linked_class=c,
                        src='Canvas',
                        auth_data=s
                    )
    Log.objects.create(user=request.user, date=datetime.datetime.now(), message="Refreshed Canvas Classes", error=False, log_type="Canvas Refresh", ip_address = request.META.get("REMOTE_ADDR"))
    return JsonResponse({"message": "Canvas classes refreshed successfully"})

@login_required(login_url='/login')
def canvas_hw(request):
    try:
        c = SchoologyClasses.objects.filter(schoology_user=request.user, src='Canvas').exclude(update=False)
    except:
        return render(request, 'hwapp/error.html', {
            'error': 'No Canvas Classes found. Please contact website admin for access'
        })
    existing_hws = Homework.objects.filter(hw_user=request.user, external_src="Canvas")
    z = []

    for existing_hw in existing_hws:
        z.append(str(existing_hw.external_id))
    for class1 in c:
        url = f"https://canvas.instructure.com/api/v1/courses/{class1.class_id}/assignments?access_token={class1.auth_data.s_secret_key}&per_page=1000" # type: ignore
        headers = {
            "Authorization": f'Bearer {class1.auth_data.s_secret_key}' # type: ignore
        }   
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        error = str(response) != "<Response [200]>"

        t = Preferences.objects.get(preferences_user=request.user)
        for hw in data:
            try:
                str(hw['id'])
            except TypeError:
                class1.update = False
                class1.save()
                break
            if str(hw['id']) not in z:
                try:
                    l = datetime.datetime.strptime(hw['due_at'], "%Y-%m-%dT%H:%M:%S%z")
                except:
                    l = datetime.datetime.now()
                try:
                    l = l.astimezone(pytz.timezone(f'{t.user_timezone}')).replace(tzinfo=None)
                except:
                    return render(request, 'hwapp/error.html', {
                        "error": "Please set timezone <a href='/preferences'>here</a>"
                    })
                h = Homework.objects.create(
                    hw_user=request.user,
                    hw_class=class1.linked_class,
                    hw_title=hw['name'],
                    external_id=hw['id'],
                    external_src="Canvas",
                    due_date=l,
                    notes=f"{hw['description']}",
                    completed=False,
                    overdue=False
                )
                IntegrationLog.objects.create(
                    user=class1.schoology_user,
                    src="canvas",
                    dest="hwapp",
                    url = url,
                    date = datetime.datetime.now(),
                    message=response.text,
                    error=error,
                    hw_name=h.hw_title
                )
                try:
                    notion_push(hw=h,user=request.user)
                except:
                    pass
            pass
    Log.objects.create(user=request.user, date=datetime.datetime.now(), message="Refreshed Canvas Homework", error=False, log_type="Canvas Refresh", ip_address = request.META.get("REMOTE_ADDR"))
    return JsonResponse({"message": "Canvas homework refreshed successfully"})
    
@login_required(login_url='/login')
def canvas_api(request):
    if request.method == 'POST':
        s_obj = SchoologyAuth(src = "Canvas", h_user = request.user) 
        s_obj.s_secret_key = request.POST.get('secret_key')
        s_obj.url = request.POST.get('base_url')
        s_obj.save()
        return render(request, 'hwapp/success.html', {
            "message": "Success! Your Canvas key has been updated"
        })   
    else:
        return render(request, 'hwapp/canvas_api.html', {
            'service': 'Canvas',
            'location': 'Profile -> Settings -> Add New Access Token',
            'prefix': 'New'
        })
@login_required(login_url='/login')
def schoology_api(request):
    if request.method == 'POST':
        try:
            s_obj = SchoologyAuth.objects.get(h_user=request.user, src="Schoology")
        except:
            s_obj = SchoologyAuth(src = "Schoology", h_user = request.user)
        
        s_obj.s_consumer_key = request.POST.get('consumer_key')
        s_obj.s_secret_key = request.POST.get('secret_key')
        s_obj.user_id = request.POST.get('user_id')
        s_obj.url = request.POST.get('base_url')

        s_obj.save()
        return render(request, 'hwapp/success.html', {
            "message": "Success! Your Schoology key has been updated"
        })
    else:
        return render(request, 'hwapp/schoology_api.html', {
            'service': 'Schoology',
        })

@login_required(login_url='/login')
def edit_api(request, integration_id):
    if request.method == 'GET':
        try:
            integration = SchoologyAuth.objects.get(id=integration_id, h_user=request.user)
        except:
            return render(request, 'hwapp/error.html', {
                'error': "You are not authorized to access this page. Click <a href='/'>here</a> to return home."
            })
        try:
            linked_classes = SchoologyClasses.objects.filter(auth_data=integration, schoology_user=request.user).exclude(update=False)
        except:
            linked_classes = False
        if integration.src == "Schoology":
            return render(request, 'hwapp/schoology_api.html', {
                'integration': integration,
                'service': integration.src,
                'linked_classes': linked_classes
            })
        else:
            return render(request, 'hwapp/canvas_api.html', {
                'integration': integration,
                'service': integration.src,
                'linked_classes': linked_classes
            })
    elif request.method == 'POST':
        try:
            s_obj = SchoologyAuth.objects.get(id=integration_id, h_user=request.user)
        except:
            return render(request, 'hwapp/error.html', {
                'error': "You are not authorized to access this page. Click <a href='/'>here</a> to return home."
            })
        if s_obj.src == "Canvas":
            s_obj.s_secret_key = request.POST.get('secret_key')
            s_obj.url = request.POST.get('base_url')
        elif s_obj.src == "Schoology":
            s_obj.s_consumer_key = request.POST.get('consumer_key')
            s_obj.s_secret_key = request.POST.get('secret_key')
            s_obj.user_id = request.POST.get('user_id')
            s_obj.url = request.POST.get('base_url')

        s_obj.save()
        return render(request, 'hwapp/success.html', {
            "message": f"{s_obj.url} updated successfully"
        }) 
    else:
        return JsonResponse({"error": "method not allowed"}, status=405)
@login_required(login_url='/login')
def csv_export(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="homework.csv"'
    hws = Homework.objects.filter(hw_user=request.user)
    class_id = request.GET.get("class_id")
    if request.GET.get("class_id"):
        try:
            hw_class = Class.objects.get(id=request.GET.get("class_id"), class_user=request.user)
            hws = hws.filter(hw_class=hw_class)
        except:
            return render(request, 'hwapp/error.html', {
                "error": "Access Denied",
            })
    #default: no completed filter
    if str(request.GET.get("completed")) == 'true':
        hws = hws.filter(completed = True)
    elif str(request.GET.get("completed")) == 'false':
        hws = hws.filter(completed = False)
    writer = csv.writer(response)
    writer.writerow(['hw_class', 'hw_title', 'due_date', 'completed'])
    hws = hws.values_list('hw_class__class_name', 'hw_title', 'due_date', 'completed')
    for hw in hws:
        writer.writerow(hw)
    return response

@user_passes_test(superuser)
def integration_log(request):
    #not authorized for non-admins
    if not request.user.is_superuser:
        return render(request, '404.html')
    if request.GET.get("error") == 'true':
        logs = IntegrationLog.objects.filter(error=True).order_by("-id")
    else:
        logs = IntegrationLog.objects.all().order_by("-id")
    Log.objects.create(
        user=request.user,
        date=datetime.datetime.now(),
        message="Viewed Integration Log",
        error=False,
        log_type="Integration Log Access",
        ip_address = request.META.get("REMOTE_ADDR")
    )
    return render(request, 'hwapp/integrationlog.html', {
        "logs": logs,
    })
@user_passes_test(superuser)
def integration_log_view(request, log_id):
    #not authorized for non-admins
    if not request.user.is_superuser:
        return render(request, '404.html')
    try:
        log = IntegrationLog.objects.get(id=log_id)
    except:
        return render(request, 'hwapp/error.html', {
            'error': f"Log ID {log_id} Not Found"
        })
    return render(request, 'hwapp/integrationlog_view.html', {
        "log": log,
    })

@user_passes_test(superuser)
def gradescope_init(request):
    if request.method == "POST":
        for entry in request.POST:
            if entry == "csrfmiddlewaretoken":
                continue
            class_id = request.POST.get(entry)
            gclasses = [i.class_id for i in GradescopeClasses.objects.filter(user=request.user)]
            try:
                if '-1' not in str(class_id):
                    class1 = Class.objects.get(id=class_id, class_user = request.user)
                    if str(entry) not in str(gclasses):
                        gs_class = GradescopeClasses.objects.create(user=request.user, linked_class=class1, class_name=class1.class_name, active=True, class_id=entry)
                        gs_class.save()
            except Exception as e:
                print(e)
                return render(request, 'hwapp/error.html', {
                    "error": "Access Denied",
                })
        return render(request, 'hwapp/success.html', {
            "message": "Gradescope Classes Added Successfully"
        })
    else:
        # step 1: get authenticity token
        url = "https://www.gradescope.com"
        response = requests.get(url)
        cookie = response.cookies
        soup = BeautifulSoup(response.text, 'html.parser')
        token = 0
        for f in soup.find_all('form'):
            if f.get('action') == '/login': # type: ignore
                for val in f.find_all('input'): # type: ignore
                    if val.get('name') == "authenticity_token": # type: ignore
                        token = val.get('value') # type: ignore
        url = 'https://www.gradescope.com/login'
        try:
            creds = GradescopeCredentials.objects.get(user=request.user)
            gs_classes = GradescopeClasses.objects.filter(user=request.user)
        except Exception as e:
            return JsonResponse({"error": "No Gradescope Credentials Found"}, status=400)
        email = creds.email
        password = creds.password
        body = {
            'utf8': '✓',
            'authenticity_token': token,
            'session[email]': email,
            'session[password]': password,
            'session[remember_me]': 0,
            'commit': 'Log In',
            'session[remember_me_sso]': 0
        }
        # step 2: log in
        res = requests.post(url, headers=g_headers, data=body, cookies=cookie)
        soup = BeautifulSoup(res.text, 'html.parser')
        gclasses = []
        name = ""
        syncedClasses = [i.class_id for i in gs_classes]
        #2.1 parse HTML for classes
        for class1 in soup.find_all('a'):
            if 'courseBox' in str(class1.get("class")): # type: ignore
                s = BeautifulSoup(str(class1), 'html.parser')
                for subhead in s.find_all('h3'):
                    name = subhead.text
                    break
                if str(class1.get('href').replace('/courses/', '')) not in str(syncedClasses): # type: ignore
                    gclasses.append((class1.get('href').replace('/courses/', ''), name)) # type: ignore
        return render(request, 'hwapp/gradescope_init.html', {
            "gclasses": gclasses,
            "classes": Class.objects.filter(class_user=request.user, archived=False)
        })
