import os
from datetime import date
import datetime
from .models import Homework, Class, Preferences, EmailTemplate
import requests
from time import time
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import sys
import pytz 
import secrets
import json
sys.path.append("..")
from integrations.views import notion_push
from integrations.models import SchoologyAuth, SchoologyClasses, IntegrationLog
from azure.communication.email import EmailClient

domain_name = {os.environ.get("DOMAIN_NAME")}

def overdue_check():
    my_date = datetime.datetime.now()
    day = my_date.strftime("%d")
    month = my_date.strftime("%m")
    year = my_date.strftime("%Y")
    #day-1 as this refresh runs midnight PST/0700 UTC for all hw due previous day
    allhw = Homework.objects.filter(due_date__date__lt=datetime.datetime(int(year), int(month), int(day)-1), completed=False)
    for hw in allhw:
        hw.overdue = True
        hw.save()
client = EmailClient.from_connection_string(os.environ.get("AZURE_CONNECTION_STRING", ""))


def send_email(interval=0):
    #load data from .env to get API key
    load_dotenv()
    #refresh ICS
    try:
        recipients = Preferences.objects.all()
        for recipient in recipients:
            listed= f'Homework email for {recipient.preferences_user.username}'
            #get all hw for recipient
            hw_list = Homework.objects.filter(hw_user=recipient.preferences_user, completed=False).order_by('due_date', 'hw_class__period', 'priority')
            #iterate over each hw item, adding it to the email in HTML format
            listed = "<ul>"
            for each in hw_list:
                if each.overdue:
                    listed += (
                        f"<li style='color:red'><a style='color:red' href='https://{os.environ.get('website_root')}/homework/{each.id}'>" # type: ignore
                        f"{each.hw_title} for {each.hw_class} is due at {each.due_date.strftime('%d %B, %Y, %I:%M %p')}</a></li>" # type: ignore
                    )
                else:
                    listed += (
                        f"<li><a href='https://{os.environ.get('website_root')}/homework/{each.id}'>" # type: ignore
                        f"{each.hw_title} for {each.hw_class}" # type: ignore
                        f"is due at {each.due_date.strftime('%d %B, %Y, %I:%M %p')}</a></li>" # type: ignore
                    )
            #add closing tag
            listed = f"{listed}</ul>"
            html_content = str(EmailTemplate.objects.get(id=2).template_body)
            html_content = html_content.replace('$$homework', listed)
            todays = date.today()
            message = {
                "content": {
                    "subject": f"{recipient.preferences_user.username}'s Homework Email for {todays}",
                    "html": html_content
                },
                "recipients": {
                    "to": [
                        {
                            "address": recipient.preferences_user.email,
                            "displayName": f"{recipient.preferences_user.first_name} {recipient.preferences_user.last_name}"
                        }
                    ]
                },
                "senderAddress": f"support@email.{domain_name}"
            }
            poller = client.begin_send(message)
            result = poller.result()
            return result
    except:
        #pass if no recipients matching preference query
        return None

def pw_reset_email(user, hash_val, expires, email):
    pw_email_template = str(EmailTemplate.objects.get(id=1).template_body)
    listed = pw_email_template.replace('$$exp_time', expires.strftime('%d %B, %Y, %I:%M %p'))
    listed = listed.replace('$$pw_reset_link', f'https://{os.environ.get("website_root", "")}/reset_password?hash={hash_val}')
    listed = listed.replace('$$website_root', os.environ.get("website_root", ""))
    #listed = f"<h1>Password Reset Email for {user.username}:</h1><br>Please navigate to the below link to reset your password. Please note that this link expires at {expires}: <br><a href='{os.environ.get('website_root')}/reset_password?hash={hash_val}'>{os.environ.get('website_root')}/reset_password?hash={hash_val}</a>"
    send = requests.post(
        f"{os.environ.get('API_BASE_URL')}/messages",
            auth=HTTPBasicAuth("api", f"{os.environ.get('mailgun_api_key')}"),
            data={
                "from": f"Homework App <noreply@{domain_name}",
                "to": [email],
                "subject": f"{user}'s Password Reset Email",
                "html": listed 
            }      
    )
def email_user(email, content, subject, recipient_name):
    message = {
        "content": {
            "subject": subject,
            "html": content
        },
        "recipients": {
            "to": [
                {
                    "address": email,
                    "displayName": recipient_name
                }
            ]
        },
        "senderAddress": f"support@email.{domain_name}",
        "replyTo": [
            {
                "address": f"support@{domain_name}",  # Email address. Required.
                "displayName": "Homework App Support"  
            }
        ]
    }
    poller = client.begin_send(message)
    return poller.result()

def timezone_helper(u_timezone, u_datetime):
    local_time = pytz.timezone(str(u_timezone))    
    local_datetime = local_time.localize(u_datetime, is_dst=None)
    utc_datetime = local_datetime.astimezone(pytz.utc)
    return utc_datetime
def email_admin(f_name, l_name, email, message):
    content = f"First Name: {f_name}<br>Last Name: {l_name}<br>Email: {email}<br>Message: {message}"
    message = {
        "content": {
            "subject": f"[{domain_name}] New Help Form Submitted",
            "html": content
        },
        "recipients": {
            "to": [
                {
                    "address": f"product@{domain_name}",
                    "displayName": f"Homework App Support"
                }
            ]
        },
        "senderAddress": f"support@email.{domain_name}"
    }
    poller = client.begin_send(message)
    result = poller.result()

def schoology_class():
    users = SchoologyAuth.objects.filter(src='Schoology')
    for s in users:
        url = f'https://api.schoology.com/v1/users/{s.user_id}/sections'
        headers = {
            "Authorization": f'OAuth realm="Schoology API",oauth_consumer_key="{s.s_consumer_key}",oauth_token="",oauth_nonce="{secrets.token_urlsafe()}",oauth_timestamp="{int(time())}",oauth_signature_method="PLAINTEXT",oauth_version="1.0",oauth_signature="{s.s_secret_key}%26"'
        }
        response = requests.get(url, headers=headers)
        response = json.loads(response.text)
        s_class = SchoologyClasses.objects.filter(schoology_user=s.h_user)
        classes = []
        for i in s_class:
            classes.append(i.class_id)
        for i in response['section']:
            if f"{i['id']}" not in str(classes):
                c = Class.objects.create(class_user=s.h_user, class_name=i['course_title'], external_src="Schoology", external_id=i['id'])
                SchoologyClasses.objects.create(schoology_user=s.h_user, class_id=i['id'], s_class_name=i['course_title'],s_grading_period=i['grading_periods'][0], linked_class=c)

def schoology_hw():
    users = SchoologyAuth.objects.filter(src='Schoology')
    for s in users:
        c = SchoologyClasses.objects.filter(schoology_user=s.h_user, src='Schoology').exclude(update=False)
        try:
            existing_hws = Homework.objects.filter(hw_user=s.h_user, external_src="Schoology")
            z = []

            for existing_hw in existing_hws:
                z.append(str(existing_hw.external_id))
            for class1 in c:
                url = f"https://api.schoology.com/v1/sections/{class1.class_id}/assignments?start=0&limit=1000"
                headers = {
                    "Authorization": f'OAuth realm="Schoology API",oauth_consumer_key="{s.s_consumer_key}",oauth_token="",oauth_nonce="{secrets.token_urlsafe()}",oauth_timestamp="{int(time())}",oauth_signature_method="PLAINTEXT",oauth_version="1.0",oauth_signature="{s.s_secret_key}%26"'
                }   
                response = requests.get(url, headers=headers)
                if str(response) != "<Response [200]>":
                    error = True
                else:
                    error = False
                data = json.loads(response.text)
                for hw in data['assignment']:                  
                    if str(hw['id']) not in z:
                        try:
                            l = datetime.datetime.strptime(hw['due'], "%Y-%m-%d %H:%M:%S")
                        except:
                            l = datetime.datetime.now()
                        h = Homework.objects.create(hw_user=s.h_user,hw_class=class1.linked_class,hw_title=hw['title'], external_id=hw['id'], external_src="Schoology", due_date=l,notes=f"{hw['description']}, {hw['web_url']}",completed=False, overdue=False)
                        IntegrationLog.objects.create(user=class1.schoology_user, src="schoology", dest="hwapp", url = url, date = datetime.datetime.now(), message=response.text, error=error)
                        try:
                            notion_push(hw=h,user=s.h_user)
                        except:
                            pass
                    pass
        except:
            pass
def canvas_class():
    all = SchoologyAuth.objects.filter(src='Canvas')
    for s in all:
        url = f'https://canvas.instructure.com/api/v1/courses?access_token={s.s_secret_key}'
        headers = {
            "Authorization": f'Bearer {s.s_secret_key}'
        }
        response = requests.get(url, headers=headers)
        #print(response.text)
        response = json.loads(response.text)
        s_class = SchoologyClasses.objects.filter(schoology_user=all.h_user, src='Canvas') # type: ignore
        classes = []
        for i in s_class:
            classes.append(str(i.class_id))
        for i in response:
            try:
                assert i['access_restricted_by_date'] == True
            except KeyError:
                if str(i['id']) not in classes:
                    c = Class.objects.create(class_user=all.h_user, class_name=i['name'], external_src="Canvas", external_id=i['id']) # type: ignore
                    SchoologyClasses.objects.create(
                        schoology_user=all.h_user,  # type: ignore
                        class_id=i['id'], 
                        s_class_name=i['name'],
                        s_grading_period=i['enrollment_term_id'], 
                        linked_class=c, 
                        src='Canvas', 
                        auth_data=s
                    )

def canvas_hw():
    c = SchoologyClasses.objects.filter(src='Canvas').exclude(update=False)
    c = [s_class for s_class in c if s_class.linked_class.archived != True] # type: ignore
    for class1 in c:
        existing_hws = Homework.objects.filter(hw_user=class1.schoology_user, external_src="Canvas")
        z = []
        for existing_hw in existing_hws:
            z.append(str(existing_hw.external_id))
        url = f"https://canvas.instructure.com/api/v1/courses/{class1.class_id}/assignments?access_token={class1.auth_data.s_secret_key}" # type: ignore
        headers = {
            "Authorization": f'Bearer {class1.auth_data.s_secret_key}' # type: ignore
        }   
        response = requests.get(url, headers=headers)
        if str(response) != "<Response [200]>":
            error = True
        else:
            error = False
        data = json.loads(response.text)
        if str(response) != "<Response [200]>":
            IntegrationLog.objects.create(user=class1.schoology_user, hw_name=f"Canvas Class Error: {class1.s_class_name}", src="canvas", dest="hwapp", url = url, date = datetime.datetime.now(), message=response.text, error=True)
            class1.update = False
            class1.save()
            break
        for hw in data:
            if str(hw['id']) not in z:
                try:
                    l = datetime.datetime.strptime(hw['due_at'], "%Y-%m-%dT%H:%M:%S%z")
                except:
                    l = datetime.datetime.now()
                h = Homework.objects.create(hw_user=class1.schoology_user,hw_class=class1.linked_class,hw_title=hw['name'], external_id=hw['id'], external_src="Canvas", due_date=l,notes=f"{hw['description']}",completed=False, overdue=False)

                IntegrationLog.objects.create(user=class1.schoology_user, src="canvas", dest="hwapp", url = url, date = datetime.datetime.now(), message=response.text, error=error)
                try:
                    notion_push(hw=h,user=class1.schoology_user)
                except:
                    pass #no notion data
            pass
