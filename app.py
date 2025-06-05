from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models import User, Ticket, Comment, Category, db
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///support.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'home'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('home.html')

@app.route('/choose_role/<action>')
def choose_role(action):
    if action not in ['login', 'register']:
        flash('Invalid action.', 'danger')
        return redirect(url_for('home'))
    admin_endpoint = f"admin_{action}"
    user_endpoint = f"user_{action}"
    return render_template('choose_role.html', action=action, admin_endpoint=admin_endpoint, user_endpoint=user_endpoint)

# Admin login/register routes
@app.route('/login/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='Admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Admin login successful.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('login_admin.html')

@app.route('/register/admin', methods=['GET', 'POST'])
def admin_register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('admin_register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('admin_register'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose another one.', 'danger')
            return redirect(url_for('admin_register'))
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='Admin'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Admin registration successful. Please login.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('register_admin.html')

# User login/register routes
@app.route('/login/user', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='User').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('User login successful.', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid user credentials.', 'danger')
    return render_template('login_user.html')
#AMIN ROUTE
@app.route('/register/user', methods=['GET', 'POST'])
def user_register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('user_register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('user_register'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose another one.', 'danger')
            return redirect(url_for('user_register'))
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='User'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User registration successful. Please login.', 'success')
        return redirect(url_for('user_login'))
    return render_template('register_user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        abort(403)

    categories = Category.query.all()
    category_id = request.args.get('category', type=int)

    # Load tickets with comments in one go (for performance and safety)
    ticket_query = Ticket.query.options(joinedload(Ticket.comments))

    if category_id:
        ticket_query = ticket_query.filter_by(category_id=category_id)

    tickets = ticket_query.all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            ticket_id = request.form.get('ticket_id', type=int)
            ticket = Ticket.query.get_or_404(ticket_id)

            title = request.form.get('title')
            description = request.form.get('description')
            status = request.form.get('status')
            category_id_form = request.form.get('category_id', type=int)

            updated = False
            if title:
                ticket.title = title
                updated = True
            if description:
                ticket.description = description
                updated = True
            if status:
                ticket.status = status
                updated = True
            if category_id_form is not None:
                ticket.category_id = category_id_form
                updated = True

            if updated:
                db.session.commit()
                flash('Ticket updated successfully.', 'success')
            else:
                flash('No fields were provided to update.', 'warning')

            return redirect(url_for('admin_dashboard'))

        elif action == 'delete':
            ticket_id = request.form.get('ticket_id', type=int)
            ticket = Ticket.query.get_or_404(ticket_id)
            db.session.delete(ticket)
            db.session.commit()
            flash('Ticket deleted successfully.', 'success')
            return redirect(url_for('admin_dashboard'))

        elif action == 'create':
            title = request.form.get('title')
            description = request.form.get('description')
            status = request.form.get('status', 'Open')
            category_id_form = request.form.get('category_id', type=int)

            if not title or not description:
                flash('Title and description are required.', 'danger')
            else:
                new_ticket = Ticket(
                    title=title,
                    description=description,
                    user_id=None,
                    status=status,
                    category_id=category_id_form
                )
                db.session.add(new_ticket)
                db.session.commit()
                flash('Ticket created successfully.', 'success')

            return redirect(url_for('admin_dashboard'))

        elif action == 'add_comment':
            ticket_id = request.form.get('ticket_id', type=int)
            content = request.form.get('comment_content')

            if ticket_id is None:
                flash('Ticket ID is missing.', 'danger')
                return redirect(url_for('admin_dashboard'))

            ticket = Ticket.query.get(ticket_id)
            if not ticket:
                flash('Ticket not found.', 'danger')
                return redirect(url_for('admin_dashboard'))

            if not content:
                flash('Comment cannot be empty.', 'danger')
                return redirect(url_for('admin_dashboard'))

            comment = Comment(ticket_id=ticket_id, user_id=current_user.id, content=content)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))

    # Final packaging: [(ticket, username, category_name)]
    tickets_with_user = []
    for t in tickets:
        user = User.query.get(t.user_id) if t.user_id else None
        category = Category.query.get(t.category_id)
        tickets_with_user.append(
            (t, user.username if user else "Unassigned", category.name if category else "Unknown")
        )

    return render_template(
        'admin_dashboard.html',
        tickets=tickets_with_user,
        categories=categories,
        selected_category=category_id
    )

# Admin create ticket (separate from dashboard)
@app.route('/admin/create_ticket', methods=['GET', 'POST'])
@login_required
def admin_create_ticket():
    if current_user.role != 'Admin':
        abort(403)

    categories = Category.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        status = request.form.get('status', 'Open')
        category_id = request.form.get('category_id', type=int)

        if not title or not description or not category_id:
            flash('All fields are required.', 'danger')
        else:
            new_ticket = Ticket(
                title=title,
                description=description,
                status=status,
                created_at=datetime.utcnow(),
                user_id=current_user.id,
                category_id=category_id,
                created_by='admin'
            )
            db.session.add(new_ticket)
            db.session.commit()
            flash('Admin ticket created successfully.', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin_create_ticket.html', categories=categories)

# User dashboard route - show tickets created by user with same interface as admin dashboard (no create ticket here)
@app.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if current_user.role != 'User':
        abort(403)

    categories = Category.query.all()
    category_id = request.args.get('category', type=int)
    # Only tickets created by current user
    if category_id:
        tickets = Ticket.query.filter_by(user_id=current_user.id, category_id=category_id).all()
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            ticket_id = request.form.get('ticket_id', type=int)
            ticket = Ticket.query.get_or_404(ticket_id)

            if ticket.user_id != current_user.id:
                abort(403)

            title = request.form.get('title')
            description = request.form.get('description')
            status = request.form.get('status')
            category_id_form = request.form.get('category_id', type=int)

            updated = False

            if title:
                ticket.title = title
                updated = True
            if description:
                ticket.description = description
                updated = True
            if status:
                ticket.status = status
                updated = True
            if category_id_form is not None:
                ticket.category_id = category_id_form
                updated = True

            if updated:
                db.session.commit()
                flash('Ticket updated successfully.', 'success')
            else:
                flash('No fields were provided to update.', 'warning')

            return redirect(url_for('user_dashboard'))

        elif action == 'delete':
            ticket_id = request.form.get('ticket_id', type=int)
            ticket = Ticket.query.get_or_404(ticket_id)

            if ticket.user_id != current_user.id:
                abort(403)

            db.session.delete(ticket)
            db.session.commit()
            flash('Ticket deleted successfully.', 'success')
            return redirect(url_for('user_dashboard'))

        elif action == 'add_comment':
            ticket_id = request.form.get('ticket_id', type=int)
            content = request.form.get('comment_content')

            if ticket_id is None:
                flash('Ticket ID is missing.', 'danger')
                return redirect(url_for('user_dashboard'))

            ticket = Ticket.query.get(ticket_id)
            if not ticket or ticket.user_id != current_user.id:
                flash('Ticket not found or unauthorized.', 'danger')
                return redirect(url_for('user_dashboard'))

            if not content:
                flash('Comment cannot be empty.', 'danger')
                return redirect(url_for('user_dashboard'))

            comment = Comment(ticket_id=ticket_id, user_id=current_user.id, content=content)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added successfully.', 'success')
            return redirect(url_for('user_dashboard'))

    tickets_with_user = []
    for t in tickets:
        user = User.query.get(t.user_id) if t.user_id else None
        category = Category.query.get(t.category_id)
        tickets_with_user.append((t, user.username if user else "Unassigned", category.name if category else "Unknown"))

    return render_template('user_dashboard.html', tickets=tickets, categories=categories, selected_category=category_id)

# User create ticket (separate from dashboard)
@app.route('/user/create_ticket', methods=['GET', 'POST'])
@login_required
def user_create_ticket():
    if current_user.role != 'User':
        abort(403)

    categories = Category.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        status = request.form.get('status', 'Open')
        category_id = request.form.get('category_id', type=int)

        if not title or not description or not category_id:
            flash('All fields are required.', 'danger')
        else:
            new_ticket = Ticket(
                title=title,
                description=description,
                status=status,
                created_at=datetime.utcnow(),
                user_id=current_user.id,
                category_id=category_id,
                created_by='user'
            )
            db.session.add(new_ticket)
            db.session.commit()
            flash('Ticket created successfully.', 'success')
            return redirect(url_for('user_dashboard'))

    return render_template('user_create_ticket.html', categories=categories)

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/show_users')
def show_users():
    users = User.query.all()
    return '<br>'.join([f'{u.id} - {u.username} - {u.email} - {u.role}' for u in users])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
