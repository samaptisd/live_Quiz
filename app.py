import eventlet
eventlet.monkey_patch()
import logging
# Configure logging: adjust level, format, and file handler as needed.
logging.basicConfig(
    level=logging.DEBUG,  # Use DEBUG or INFO for detailed logs
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("live_contest.log"),  # Log file
        logging.StreamHandler()  # Console output
    ]
)
import uuid, random, os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bson.objectid import ObjectId
import qrcode
from datetime import datetime, timedelta
import pytz



app = Flask(__name__)
app.secret_key = ''
app.config['MONGO_URI'] = 'mongodb://admin:Password@localhost:27017/live_contest?authSource=admin'
mongo = PyMongo(app)
# socketio = SocketIO(app)

# socketio = SocketIO(app, message_queue='redis://')
socketio = SocketIO(
    app,
    async_mode='eventlet',
    message_queue='redis://',
    logger=True,
    engineio_logger=True,
    cors_allowed_origins="*"
)


# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user model for demonstration
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

def get_user(username):
    user_doc = mongo.db.auth.find_one({"username": username})
    if user_doc:
        return User(str(user_doc['_id']), user_doc['username'], user_doc['password'])
    return None

@login_manager.user_loader
def load_user(user_id):
    user_doc = mongo.db.auth.find_one({"_id": ObjectId(user_id)})
    if user_doc:
        return User(str(user_doc['_id']), user_doc['username'], user_doc['password'])
    return None


@app.template_filter('mask_phone')
def mask_phone(phone):
    phone = str(phone)
    if len(phone) < 7:
        return phone  # not enough digits to mask
    return phone[:3] + 'xxx' + phone[-4:]



@app.template_filter('utc_to_ist')
def utc_to_ist(utc_value):
    # If utc_value is a string, parse it; adjust the format as needed
    if isinstance(utc_value, str):
        try:
            utc_dt = datetime.strptime(utc_value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            utc_dt = datetime.strptime(utc_value, "%Y-%m-%dT%H:%M:%SZ")
    else:
        utc_dt = utc_value

    # Set UTC timezone and convert to IST
    utc_zone = pytz.timezone('UTC')
    ist_zone = pytz.timezone('Asia/Kolkata')
    utc_dt = utc_zone.localize(utc_dt)
    ist_dt = utc_dt.astimezone(ist_zone)
    # Format the output as needed
    return ist_dt.strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------
# Authentication Routes (login/logout)
# ---------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user(username)
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

# ---------------------------
# Quiz Set Creation (Reusable Question Set)
# ---------------------------
@app.route('/create_quiz_set', methods=['GET', 'POST'])
@login_required
def create_quiz_set():
    if request.method == 'POST':
        quiz_title = request.form.get('title')
        # Gather list fields for each question block
        question_text_list = request.form.getlist('question_text')
        options_list = request.form.getlist('options')
        correct_option_list = request.form.getlist('correct_option')
        questions = []
        for q_text, opts, corr in zip(question_text_list, options_list, correct_option_list):
            options_split = [line.strip() for line in opts.splitlines() if line.strip()]
            questions.append({
                'question_text': q_text,
                'options': options_split,
                'correct_option': corr
            })
        quiz_set_doc = {
            'quiz_set_id': str(uuid.uuid4()),
            'title': quiz_title,
            'host': current_user.username,
            'questions': questions,
            'created_at': datetime.utcnow()
        }
        mongo.db.quiz_sets.insert_one(quiz_set_doc)
        flash('Quiz set created successfully!')
        return redirect(url_for('list_quiz_sets'))
    return render_template('create_quiz_set.html')

# View Quiz Sets
@app.route('/quiz_sets')
@login_required
def list_quiz_sets():
    # Get all quiz sets for the current host.
    quiz_sets = list(mongo.db.quiz_sets.find({'host': current_user.username}))
    # For each quiz set, find its associated sessions.
    for qs in quiz_sets:
        sessions = list(mongo.db.quiz_sessions.find({'quiz_set_id': qs['quiz_set_id']}))
        qs['sessions'] = sessions
    return render_template('quiz_sets.html', quiz_sets=quiz_sets)


@app.route('/view_quiz_set/<quiz_set_id>')
@login_required
def view_quiz_set(quiz_set_id):
    # Find the quiz set from the database
    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': quiz_set_id})
    
    # If the quiz set does not exist, redirect or show an error
    if not quiz_set:
        flash("Quiz set not found")
        return redirect(url_for('list_quiz_sets'))
    
    # Add letters (A, B, C, D) to each option
    for question in quiz_set['questions']:
        question['options_with_letters'] = list(zip(['A', 'B', 'C', 'D'], question['options']))
    
    return render_template('view_quiz_set.html', quiz_set=quiz_set)




@app.route('/quiz_session_history/<quiz_set_id>')
@login_required
def quiz_session_history(quiz_set_id):
    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': quiz_set_id})
    if not quiz_set:
        flash("Quiz set not found")
        return redirect(url_for('list_quiz_sets'))
    quiz_sessions = list(mongo.db.quiz_sessions.find({'quiz_set_id': quiz_set_id}))
    return render_template('quiz_sessions_history.html', quiz_set=quiz_set, quiz_sessions=quiz_sessions)


# ---------------------------
# Quiz Session Creation (Instance of a Quiz Set)
# ---------------------------
@app.route('/start_session/<quiz_set_id>', methods=['GET', 'POST'])
@login_required
def start_session(quiz_set_id):
    # Retrieve quiz set details
    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': quiz_set_id})
    if not quiz_set:
        flash("Quiz set not found")
        return redirect(url_for('list_quiz_sets'))
    
    if request.method == 'POST':
        session_name = request.form.get('session_name')
        session_doc = {
            'session_id': str(uuid.uuid4()),
            'quiz_set_id': quiz_set_id,
            'session_name': session_name,
            'join_code': str(random.randint(1000, 9999)),
            'participants': [],
            'status': 'not_started',  # not_started, live, ended
            'created_at': datetime.utcnow(),
            'started_at': None,
            'ended_at': None
        }
        mongo.db.quiz_sessions.insert_one(session_doc)
        flash('Quiz session created!')
        # return redirect(url_for('quiz_session_details', session_id=session_doc['session_id']))
        return redirect(url_for('host_dashboard', session_id=session_doc['session_id']))
    return render_template('start_session.html', quiz_set=quiz_set)

# View details of a session (for host)
@app.route('/quiz_session/<session_id>')
@login_required
def quiz_session_details(session_id):
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        flash("Session not found")
        return redirect(url_for('list_quiz_sets'))
    # Generate QR code for session join URL
    qr_code_path = f'static/qr_codes/qr_{session_id}.png'
    if not os.path.exists(qr_code_path):
        join_url = request.host_url + 'join_session/' + session_id
        img = qrcode.make(join_url)
        img.save(qr_code_path)
    return render_template('quiz_session_details.html', session=session, qr_code=qr_code_path)

# ---------------------------
# Participant Join a Quiz Session
# ---------------------------
@app.route('/join_session/<session_id>', methods=['GET', 'POST'])
def join_session(session_id):
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        flash("Session not found")
        logging.warning("Join session failed: Session %s not found (IP: %s)", session_id, request.remote_addr)
        return redirect(url_for('login'))
    # If session is ended, show an expiration message.
    if session.get('status') == 'ended':
        logging.info("Join session request for ended session %s (IP: %s)", session_id, request.remote_addr)
        return render_template('session_expired.html', session=session)
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        logging.info("Join session request: session_id=%s, name=%s, phone=%s, IP=%s", session_id, name, phone, request.remote_addr)
        # Check if this participant already joined
        existing = mongo.db.quiz_sessions.find_one({
            'session_id': session_id,
            'participants': {'$elemMatch': {'name': name, 'phone': phone}}
        })
        if existing:
            logging.info("Duplicate join detected for session %s, name=%s, phone=%s", session_id, name, phone)
            flash("You have already joined this session.")
            return redirect(url_for('join_session', session_id=session_id))
        participant = {
            'name': name,
            'phone': phone,
            'score': 0,
            'joined_at': datetime.utcnow()
        }
        mongo.db.quiz_sessions.update_one({'session_id': session_id}, {'$push': {'participants': participant}})
        updated_session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
        # Convert datetime objects to strings
        for p in updated_session['participants']:
            if isinstance(p.get('joined_at'), datetime):
                p['joined_at'] = p['joined_at'].isoformat()
        socketio.emit('update_participants', {'participants': updated_session['participants']}, room=session_id)
        return redirect(url_for('participant_quiz', session_id=session_id, participant_name=name, phone=phone))
    return render_template('join_session.html', session=session)


@app.route('/join_by_code', methods=['GET', 'POST'])
def join_by_code():
    if request.method == 'POST':
        join_code = request.form.get('join_code')
        # Search for a session that is not ended and has the given join code.
        session = mongo.db.quiz_sessions.find_one({'join_code': join_code, 'status': {'$ne': 'ended'}})
        if session:
            # Redirect to the join session page.
            return redirect(url_for('join_session', session_id=session['session_id']))
        else:
            flash("No active session found with that join code.")
            return redirect(url_for('join_by_code'))
    return render_template('join_by_code.html')




# ---------------------------
# Participant Quiz Interface (Using Quiz Set from the Session)
# ---------------------------
@app.route('/participant/<session_id>/<participant_name>/<phone>')
def participant_quiz(session_id, participant_name, phone):
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        flash("Session not found")
        return redirect(url_for('login'))
    # If the session has ended, redirect to the session results page.
    if session.get('status') == 'ended':
        # return redirect(url_for('session_results', session_id=session_id))
        return render_template('session_expired.html', session=session)
    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': session['quiz_set_id']})
    if not quiz_set:
        flash("Quiz set not found")
        return redirect(url_for('login'))
    questions = quiz_set.get('questions', [])

    if session.get('end_time'):
        session['end_time'] = session['end_time'].isoformat() + "Z"
    currentIndex = 0
    for p in session['participants']:
        if p['name'] == participant_name and p['phone'] == phone:
            if 'answers' in p:
                currentIndex = len(p['answers'])
            break
    server_time = datetime.utcnow().isoformat() + "Z"
    return render_template('participant_quiz.html',
                           session=session,
                           quiz_set=quiz_set,
                           questions=questions,
                           participant_name=participant_name,
                           phone=phone,
                           currentIndex=currentIndex,
                           server_time=server_time)


# ---------------------------
# Host Dashboard for a Session (Real-Time Updates)
# ---------------------------
@app.route('/host/<session_id>')
@login_required
def host_dashboard(session_id):
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        flash("Session not found")
        return redirect(url_for('list_quiz_sets'))

    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': session['quiz_set_id']})
    if not quiz_set:
        flash("Quiz set not found")
        return redirect(url_for('list_quiz_sets'))

    if 'questions' not in quiz_set or quiz_set['questions'] is None:
        quiz_set['questions'] = []

    if 'participants' not in session or session['participants'] is None:
        session['participants'] = []

    session['quiz_set'] = quiz_set

    if session.get('end_time'):
        session['end_time'] = session['end_time'].isoformat() + "Z"

    qr_code_path = f'static/qr_codes/qr_{session_id}.png'
    if not os.path.exists(qr_code_path):
        join_url = request.host_url + 'join_session/' + session_id
        img = qrcode.make(join_url)
        img.save(qr_code_path)
    
    # For live sessions, use the official quiz start time from the database.
    if session.get('status') == 'live' and session.get('started_at'):
        server_time = session['started_at'].isoformat() + "Z"
    else:
        server_time = datetime.utcnow().isoformat() + "Z"

    return render_template('host_dashboard.html', session=session, qr_code=qr_code_path, server_time=server_time)




@app.route('/session_results/<session_id>')
@login_required
def session_results(session_id):
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        flash("Session not found")
        return redirect(url_for('list_quiz_sets'))
    if session.get('status') != 'ended':
        flash("Session is not ended yet. Results are not available.")
        return redirect(url_for('host_dashboard', session_id=session_id))
    
    # Query and add quiz_set data if available
    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': session['quiz_set_id']})
    if quiz_set:
        session['quiz_set'] = quiz_set
    else:
        session['quiz_set'] = {'questions': []}
    
    return render_template('session_results.html', session=session)



@app.route('/youtube')
def youtube_stream():
    return render_template("youtube.html")



# ---------------------------
# Socket.IO Events
# ---------------------------
@socketio.on('join_room')
def on_join(data):
    room = data['session_id']  # Now using session_id as room id
    join_room(room)
    logging.info("Socket join: session_id=%s, socket_id=%s, IP=%s", room, request.sid, request.remote_addr)
    emit('message', {'msg': f"A user joined session {room}"}, room=room)

@socketio.on('start_quiz')
def on_start(data):
    session_id = data['session_id']
    duration = data.get('duration', 60)  # in seconds
    current_server_time = datetime.utcnow()
    end_time = current_server_time + timedelta(seconds=duration)
    mongo.db.quiz_sessions.update_one(
        {'session_id': session_id},
        {'$set': {
            'status': 'live',
            'started_at': current_server_time,
            'duration': duration,
            'end_time': end_time
        }}
    )
    end_time_str = end_time.isoformat() + "Z"
    current_time_str = current_server_time.isoformat() + "Z"
    emit('session_status_update', {'status': 'live', 'end_time': end_time_str}, room=session_id)
    emit('quiz_started', {'msg': 'Quiz has started', 'end_time': end_time_str, 'server_time': current_time_str, 'duration': duration}, room=session_id)



@socketio.on('submit_answer')
def on_submit_answer(data):
    session_id = data['session_id']
    participant_name = data['participant_name']
    participant_phone = data['participant_phone']
    selected_option = data['selected_option']
    question_text = data.get('question_text')
    time_taken = data.get('time_taken')  # in seconds

    logging.info("Submit answer: session_id=%s, name=%s, phone=%s, option=%s, question=%s, time_taken=%s, socket_id=%s, IP=%s",
                 session_id, participant_name, participant_phone, selected_option, question_text, time_taken,
                 request.sid, request.remote_addr)

    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    if not session:
        logging.warning("Submit answer failed: Session %s not found", session_id)
        return

    quiz_set = mongo.db.quiz_sets.find_one({'quiz_set_id': session['quiz_set_id']})
    if not quiz_set:
        logging.warning("Submit answer failed: Quiz set for session %s not found", session_id)
        return

    correct = False
    correct_option = None
    for q in quiz_set['questions']:
        if q['question_text'] == question_text:
            correct_option = q.get('correct_option')
            if selected_option.strip().lower() == correct_option.strip().lower():
                correct = True
            break

    answer_obj = {
        'question': question_text,
        'selected_option': selected_option,
        'time_taken': time_taken,
        'correct': correct
    }

    update = {'$push': {'participants.$.answers': answer_obj}}
    if correct:
        update['$inc'] = {'participants.$.score': 1}

    mongo.db.quiz_sessions.update_one(
        {'session_id': session_id,
         'participants': {'$elemMatch': {'name': participant_name, 'phone': participant_phone}}},
        update
    )

    updated_session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    for p in updated_session['participants']:
        if isinstance(p.get('joined_at'), datetime):
            p['joined_at'] = p['joined_at'].isoformat()
    socketio.emit('update_participants', {'participants': updated_session['participants']}, room=session_id)




@socketio.on('end_quiz')
def on_end(data):
    session_id = data['session_id']
    logging.info("End quiz: session_id=%s, socket_id=%s, IP=%s", session_id, request.sid, request.remote_addr)
    mongo.db.quiz_sessions.update_one(
        {'session_id': session_id},
        {'$set': {'status': 'ended', 'ended_at': datetime.utcnow()}}
    )
    session = mongo.db.quiz_sessions.find_one({'session_id': session_id})
    final_scores = {}
    for p in session['participants']:
        key = p['name'] + " (" + p['phone'] + ")"
        final_scores[key] = p['score']
    emit('quiz_ended', {'msg': 'Quiz has ended', 'final_scores': final_scores}, room=session_id)

    # Emit a custom event to force clients to disconnect
    emit('force_disconnect', {}, room=session_id)






if __name__ == '__main__':
    socketio.run(app, debug=True)
