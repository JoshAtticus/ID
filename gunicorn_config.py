"""
Gunicorn configuration file for JoshAtticusID application
"""

# Server socket binding
bind = "0.0.0.0:5002"  # Same port as in Flask app

# Worker processes
workers = 4  # Rule of thumb: 2-4 x number of CPU cores
worker_class = "sync"
threads = 2

# Logging
accesslog = "/var/log/joshatticusid/access.log"
errorlog = "/var/log/joshatticusid/error.log"
loglevel = "info"

# Process naming
proc_name = "joshatticusid"

# User and group to run as
user = "www-data"
group = "www-data"

# Daemonize the Gunicorn process
daemon = True

# PID file
pidfile = "/var/run/joshatticusid/gunicorn.pid"