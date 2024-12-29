from flask import Flask, render_template, request, redirect, session, url_for, flash
from pymongo import MongoClient
from datetime import datetime
import bcrypt
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MongoDB connection
connection_string = "mongodb+srv://shalinigonugunta229:BK2rnf85AviNFast@cluster0.clbkt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(connection_string)
db = client["user_auth_system"]
users_collection = db["users"]
tasks_collection = db["tasks"]
admins_collection = db["admins"]

# Admin credentials
default_admin_username = "admin"
default_admin_password = "admin123"

# Helper Functions
def register_user(username, password):
    if users_collection.find_one({"username": username}):
        return False
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users_collection.insert_one({"username": username, "password": hashed_password})
    return True

def authenticate_user(username, password):
    user = users_collection.find_one({"username": username})
    if not user:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), user["password"])

def authenticate_admin(username, password):
    admin = admins_collection.find_one({"username": username})
    if not admin:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), admin["password"])

def create_task(username, task_name, description, priority, deadline, status, project):
    deadline = datetime.strptime(deadline, "%Y-%m-%d")
    tasks_collection.insert_one({
        "username": username,
        "task_name": task_name,
        "description": description,
        "priority": priority,
        "deadline": deadline,
        "status": status,
        "project": project,
    })

# Add default admin if not present
def add_default_admin():
    if not admins_collection.find_one({"username": default_admin_username}):
        hashed_password = bcrypt.hashpw(default_admin_password.encode("utf-8"), bcrypt.gensalt())
        admins_collection.insert_one({"username": default_admin_username, "password": hashed_password})

add_default_admin()  # Call this function to ensure the default admin is in the database.

@app.route("/", methods=["GET", "POST"])
def login_or_register():
    if session.get("logged_in"):
        return redirect(url_for("task_management"))

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")
        password = request.form.get("password")

        if action == "Register":
            confirm_password = request.form.get("confirm_password")
            if password != confirm_password:
                flash("Passwords do not match!", "danger")
                return redirect(url_for("login_or_register"))
            elif register_user(username, password):
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for("login_or_register"))
            else:
                flash("Username already exists!", "danger")
                return redirect(url_for("login_or_register"))
        elif action == "Login":
            if authenticate_user(username, password):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("task_management"))
            else:
                flash("Invalid username or password!", "danger")
                return redirect(url_for("login_or_register"))

    return render_template("login_register.html")


@app.route("/tasks", methods=["GET", "POST"])
def task_management():
    if not session.get("logged_in"):
        return redirect(url_for("login_or_register"))

    username = session.get("username")
    if request.method == "POST":
        task_name = request.form.get("task_name")
        description = request.form.get("description")
        priority = request.form.get("priority")
        deadline = request.form.get("deadline")
        status = request.form.get("status")
        project = request.form.get("project")

        if task_name:
            create_task(username, task_name, description, priority, deadline, status, project)
            flash("Task created successfully!", "success")
        else:
            flash("Task name is required!", "danger")

    tasks = list(tasks_collection.find({"username": username}))
    return render_template("tasks.html", tasks=tasks, username=username)

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if authenticate_admin(username, password):
            session["admin_logged_in"] = True
            session["admin_username"] = username
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials!", "danger")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    tasks = list(tasks_collection.find())
    users = list(users_collection.find())
    return render_template("admin_dashboard.html", tasks=tasks, users=users)

@app.route("/edit_task/<task_id>", methods=["GET", "POST"])
def edit_task(task_id):
    if not session.get("logged_in"):
        return redirect(url_for("login_or_register"))

    task = tasks_collection.find_one({"_id": ObjectId(task_id)})

    if not task or task["username"] != session["username"]:
        flash("You are not authorized to edit this task.", "danger")
        return redirect(url_for("task_management"))

    if request.method == "POST":
        task_name = request.form.get("task_name")
        description = request.form.get("description")
        priority = request.form.get("priority")
        deadline = request.form.get("deadline")
        status = request.form.get("status")
        project = request.form.get("project")

        # Validate the data
        if task_name:
            # Update task data
            update_data = {
                "task_name": task_name,
                "description": description,
                "priority": priority,
                "status": status,
                "project": project,
            }
            if deadline:
                update_data["deadline"] = datetime.strptime(deadline, "%Y-%m-%d")

            tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": update_data})
            flash("Task updated successfully!", "success")
            return redirect(url_for("task_management"))
        else:
            flash("Task name is required!", "danger")
            tasks = tasks_collection.find()
    
    # Fetch all users (you can also adjust this based on your requirements)
    users = users_collection.find()

    # Pass the data to the template
    return render_template("edit_task.html", task=task)


@app.route("/admin/edit_user/<user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username:
            update_data = {"username": username}
            if password:
                hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
                update_data["password"] = hashed_password
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
            flash("User updated successfully!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Username is required!", "danger")

    return render_template("edit_user.html", user=user)

@app.route("/delete_task/<task_id>")
def delete_task(task_id):
    if not session.get("logged_in"):
        return redirect(url_for("login_or_register"))

    # Delete task from the tasks collection
    tasks_collection.delete_one({"_id": ObjectId(task_id)})
    flash("Task deleted successfully!", "success")
    return redirect(url_for("task_management"))

@app.route("/admin_logout")
def admin_logout():
    session.clear()  # Clears all session data
    flash("You have been logged out!", "success")
    return redirect(url_for("admin_login"))

@app.route("/admin/delete_user/<user_id>")
def delete_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    users_collection.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/add_user", methods=["POST"])
def add_user():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    username = request.form.get("username")
    password = request.form.get("password")

    if username and password:
        if register_user(username, password):
            flash("User added successfully!", "success")
        else:
            flash("Username already exists!", "danger")
    else:
        flash("Both username and password are required!", "danger")

    return redirect(url_for("admin_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_or_register"))

if __name__ == "__main__":
    app.run(debug=True)
