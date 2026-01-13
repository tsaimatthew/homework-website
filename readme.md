# Homework App

[![Docker Image CI](https://github.com/matthewt-123/homework-website/actions/workflows/validate-image.yml/badge.svg)](https://github.com/matthewt-123/homework-website/actions/workflows/validate-image.yml)
[![Docker Image Deploy](https://github.com/matthewt-123/homework-website/actions/workflows/deploy-image.yml/badge.svg)](https://github.com/matthewt-123/homework-website/actions/workflows/deploy-image.yml)


**All-in-one assignment tracker and study companion.**  
Built for high school and college students to take control of their academic life.

---

## Overview

The Homework App is a Django based website that helps students manage assignments from multiple platforms in one place. It integrates with:

- **Gradescope**
- **Schoology**
- **Canvas**
- **Notion**

---

## Features

### Assignment Management
- **Import assignments** from Gradescope, Canvas, and Schoology
- **Create custom classes and assignments**
- **Manual refresh** to sync your latest submissions
- **Export all assignments to CSV**

### Personal Workspace
- **Bookmarks & custom pages** for notes or links
- **Study playlists** — create Spotify playlists tailored to your mood

### Notion Integration
- Two-way sync: view tasks in Notion and check them off when done
- Keeps your personal workflow in sync with your academic tasks

### Admin & Management Tools
- **Access group-based access control**
- **User management**
- **Custom page management** with a Site Manager interface
- **Access logging and auditing**
- **Error tracking** with [Sentry](https://sentry.io/) and [Cronitor](https://cronitor.io/)
- **Help request form** 

---

## Getting Started

1. Clone the repo:
   ```bash
   git clone https://github.com/matthewt-123/homework-app.git
   cd homework-app
2. Set up the environment 
    ```bash
    python3 -m venv env 
    source env/bin/activate 
    pip install -r requirements.txt
3. Configure .env \
    copy from .env.example
4. Run the app
    ```bash
    python manage.py migrate
    python manage.py runserver
