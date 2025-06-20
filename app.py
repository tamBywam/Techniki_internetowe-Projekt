from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Model bazy danych
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    followed_quizzes = db.relationship(
        'Quiz',
        secondary='quiz_followers',
        backref=db.backref('followers', lazy='dynamic'),
        lazy='dynamic'
    )

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    quizzes = db.relationship('Quiz', backref='category', lazy=True)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    questions = db.relationship('Question', backref='quiz', lazy=True)
    comments = db.relationship('Comment', backref='quiz', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    attempts = db.relationship('QuizAttempt', backref='question', lazy=True)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    selected_option = db.Column(db.Integer, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

quiz_followers = db.Table('quiz_followers',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('quiz_id', db.Integer, db.ForeignKey('quiz.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    categories = Category.query.all()
    popular_quizzes = Quiz.query.order_by(db.func.random()).limit(3).all()
    return render_template('index.html', categories=categories, popular_quizzes=popular_quizzes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Nieprawidłowa nazwa użytkownika lub hasło', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Nazwa użytkownika jest już zajęta', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Rejestracja zakończona sukcesem. Możesz się teraz zalogować', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    users = User.query.all()
    categories = Category.query.all()
    quizzes = Quiz.query.all()
    return render_template('admin/dashboard.html', users=users, categories=categories, quizzes=quizzes)

# CRUD dla użytkowników
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Użytkownik został usunięty', 'success')
    return redirect(url_for('admin_users'))

# CRUD dla kategorii
@app.route('/admin/categories')
@login_required
def admin_categories():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/category/add', methods=['GET', 'POST'])
@login_required
def add_category():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        if Category.query.filter_by(name=name).first():
            flash('Kategoria o tej nazwie już istnieje', 'danger')
            return redirect(url_for('add_category'))
        
        new_category = Category(name=name, description=description)
        db.session.add(new_category)
        db.session.commit()
        flash('Kategoria została dodana', 'success')
        return redirect(url_for('admin_categories'))
    
    return render_template('admin/add_category.html')

@app.route('/admin/category/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    category = Category.query.get_or_404(category_id)
    
    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form['description']
        db.session.commit()
        flash('Kategoria została zaktualizowana', 'success')
        return redirect(url_for('admin_categories'))
    
    return render_template('admin/edit_category.html', category=category)

@app.route('/admin/category/delete/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Kategoria została usunięta', 'success')
    return redirect(url_for('admin_categories'))

# CRUD dla quizów
@app.route('/admin/quizzes')
@login_required
def admin_quizzes():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    quizzes = Quiz.query.all()
    return render_template('admin/quizzes.html', quizzes=quizzes)

@app.route('/admin/quiz/add', methods=['GET', 'POST'])
@login_required
def add_quiz():
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    categories = Category.query.all()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form['category_id']
        
        if Quiz.query.filter_by(title=title).first():
            flash('Quiz o tej nazwie już istnieje', 'danger')
            return redirect(url_for('add_quiz'))
        
        new_quiz = Quiz(title=title, description=description, category_id=category_id)
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz został dodany', 'success')
        return redirect(url_for('admin_quizzes'))
    
    return render_template('admin/add_quiz.html', categories=categories)

@app.route('/admin/quiz/edit/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    categories = Category.query.all()
    
    if request.method == 'POST':
        quiz.title = request.form['title']
        quiz.description = request.form['description']
        quiz.category_id = request.form['category_id']
        db.session.commit()
        flash('Quiz został zaktualizowany', 'success')
        return redirect(url_for('admin_quizzes'))
    
    return render_template('admin/edit_quiz.html', quiz=quiz, categories=categories)

@app.route('/admin/quiz/delete/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz został usunięty', 'success')
    return redirect(url_for('admin_quizzes'))

# CRUD dla pytań
@app.route('/admin/quiz/<int:quiz_id>/questions')
@login_required
def admin_questions(quiz_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('admin/questions.html', quiz=quiz, questions=questions)

@app.route('/admin/quiz/<int:quiz_id>/question/add', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        content = request.form['content']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = int(request.form['correct_option'])
        
        new_question = Question(
            content=content,
            option1=option1,
            option2=option2,
            option3=option3,
            option4=option4,
            correct_option=correct_option,
            quiz_id=quiz_id
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Pytanie zostało dodane', 'success')
        return redirect(url_for('admin_questions', quiz_id=quiz_id))
    
    return render_template('admin/add_question.html', quiz=quiz)

@app.route('/admin/question/edit/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    question = Question.query.get_or_404(question_id)
    
    if request.method == 'POST':
        question.content = request.form['content']
        question.option1 = request.form['option1']
        question.option2 = request.form['option2']
        question.option3 = request.form['option3']
        question.option4 = request.form['option4']
        question.correct_option = int(request.form['correct_option'])
        db.session.commit()
        flash('Pytanie zostało zaktualizowane', 'success')
        return redirect(url_for('admin_questions', quiz_id=question.quiz_id))
    
    return render_template('admin/edit_question.html', question=question)

@app.route('/admin/question/delete/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if current_user.role != 'admin':
        flash('Brak uprawnień administratora', 'danger')
        return redirect(url_for('home'))
    
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Pytanie zostało usunięte', 'success')
    return redirect(url_for('admin_questions', quiz_id=quiz_id))

# Funkcjonalności użytkownika
@app.route('/quizzes')
@login_required
def browse_quizzes():
    categories = Category.query.all()
    category_id = request.args.get('category_id', type=int)
    show_followed = request.args.get('followed', type=bool, default=False)
    
    if show_followed:
        quizzes = current_user.followed_quizzes.all()
    else:
        if category_id:
            quizzes = Quiz.query.filter_by(category_id=category_id).all()
        else:
            quizzes = Quiz.query.all()
    
    return render_template('user/quizzes.html', 
                           categories=categories, 
                           quizzes=quizzes, 
                           selected_category=category_id,
                           show_followed=show_followed)

@app.route('/quiz/<int:quiz_id>')
@login_required
def quiz_detail(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    comments = Comment.query.filter_by(quiz_id=quiz_id).order_by(Comment.timestamp.desc()).all()
    return render_template('user/quiz_detail.html', quiz=quiz, comments=comments)

@app.route('/quiz/<int:quiz_id>/play', methods=['GET', 'POST'])
@login_required
def play_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if request.method == 'POST':
        score = 0
        for question in questions:
            selected_option = int(request.form.get(f'question_{question.id}'))
            is_correct = (selected_option == question.correct_option)
            
            if is_correct:
                score += 1
            
            attempt = QuizAttempt(
                user_id=current_user.id,
                question_id=question.id,
                quiz_id=quiz_id,
                selected_option=selected_option,
                is_correct=is_correct
            )
            db.session.add(attempt)
        
        db.session.commit()
        flash(f'Twój wynik: {score}/{len(questions)}', 'info')
        return redirect(url_for('quiz_detail', quiz_id=quiz_id))
    
    return render_template('user/play_quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz/<int:quiz_id>/comment', methods=['POST'])
@login_required
def add_comment(quiz_id):
    content = request.form['content']
    if not content:
        flash('Komentarz nie może być pusty', 'danger')
        return redirect(url_for('quiz_detail', quiz_id=quiz_id))
    
    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        quiz_id=quiz_id
    )
    db.session.add(new_comment)
    db.session.commit()
    flash('Komentarz został dodany', 'success')
    return redirect(url_for('quiz_detail', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>/follow', methods=['POST'])
@login_required
def follow_quiz(quiz_id):
    if not Quiz.query.get(quiz_id):
        abort(404)
    
    stmt = quiz_followers.insert().values(user_id=current_user.id, quiz_id=quiz_id)
    try:
        db.session.execute(stmt)
        db.session.commit()
        flash('Zacząłeś obserwować ten quiz', 'success')
    except:
        db.session.rollback()
        flash('Już obserwujesz ten quiz', 'warning')
    return redirect(url_for('quiz_detail', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>/unfollow', methods=['POST'])
@login_required
def unfollow_quiz(quiz_id):
    stmt = quiz_followers.delete().where(
        (quiz_followers.c.user_id == current_user.id) &
        (quiz_followers.c.quiz_id == quiz_id)
    )
    db.session.execute(stmt)
    db.session.commit()
    flash('Przestałeś obserwować ten quiz', 'info')
    return redirect(url_for('quiz_detail', quiz_id=quiz_id))

@app.route('/profile')
@login_required
def user_profile():
    quizzes_attempted = db.session.query(QuizAttempt.quiz_id)\
        .filter_by(user_id=current_user.id)\
        .distinct()\
        .count()
    
    total_questions = QuizAttempt.query.filter_by(user_id=current_user.id).count()
    
    correct_answers = QuizAttempt.query.filter_by(
        user_id=current_user.id, 
        is_correct=True
    ).count()
    
    user_stats = {
        'quizzes_attempted': quizzes_attempted,
        'total_questions': total_questions,
        'correct_answers': correct_answers
    }
    return render_template('user/profile.html', user_stats=user_stats)

@app.route('/rankings')
def rankings():
    user_ranking = db.session.query(
        User.username,
        db.func.count(QuizAttempt.id).filter(QuizAttempt.is_correct).label('correct_answers')
    ).join(QuizAttempt).group_by(User.id).order_by(db.desc('correct_answers')).limit(10).all()
    
    quiz_ranking = db.session.query(
        Quiz.title,
        db.func.count(db.distinct(QuizAttempt.user_id)).label('unique_attempts')
    ).join(QuizAttempt).group_by(Quiz.id).order_by(db.desc('unique_attempts')).limit(10).all()
    
    return render_template('user/rankings.html', user_ranking=user_ranking, quiz_ranking=quiz_ranking)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('adminpass'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True)