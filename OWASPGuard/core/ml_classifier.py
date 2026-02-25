"""
LightGBM ML Classifier for vulnerability detection
"""
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re
import ast
import json

from core.hf_vuln_classifier import HfVulnerabilityClassifier

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False
    lgb = None

class VulnerabilityClassifier:
    """
    Lightweight ML classifier for vulnerability detection
    
    Model characteristics:
    - Size: ~500KB
    - Inference: ~1ms per prediction
    - Training: ~10 seconds on 10K samples
    - Accuracy: 85-90% with proper training
    """
    
    def __init__(self, model_path: str = "models/vuln_classifier.txt"):
        self.model_path = Path(model_path)
        self.model = None
        self.label_encoders = {}

        # Hugging Face classifier (preferred when available)
        self.hf_classifier = HfVulnerabilityClassifier()

        # Load LightGBM model if it exists (kept as fallback / offline mode)
        if LIGHTGBM_AVAILABLE and self.model_path.exists():
            self.load_model()
    
    def extract_features(self, code_snippet: str, context: Dict = None) -> np.ndarray:
        """
        Extract 50 features from code snippet
        
        Feature categories:
        1. Code metrics (15): length, complexity, nesting, etc.
        2. Pattern features (20): vulnerability-specific patterns
        3. Context features (15): imports, decorators, error handling
        """
        features = []
        context = context or {}
        
        # === CODE METRICS (15 features) ===
        lines = code_snippet.split('\n')
        features.append(len(code_snippet))                    # Total characters
        features.append(len(lines))                           # Lines of code
        features.append(np.mean([len(l) for l in lines]) if lines else 0)     # Avg line length
        features.append(max([len(l) for l in lines] + [0]))   # Max line length
        features.append(code_snippet.count('    '))           # Indentation depth
        features.append(code_snippet.count('if '))            # Conditionals
        features.append(code_snippet.count('for '))           # Loops
        features.append(code_snippet.count('while '))         # While loops
        features.append(code_snippet.count('def '))           # Functions
        features.append(code_snippet.count('class '))         # Classes
        features.append(code_snippet.count('import '))        # Imports
        features.append(code_snippet.count('try:'))           # Exception handling
        features.append(code_snippet.count('except'))         # Except blocks
        features.append(len(set(code_snippet.split())))       # Unique tokens
        
        # Calculate cyclomatic complexity (simplified)
        complexity = 1
        complexity += code_snippet.count('if ')
        complexity += code_snippet.count('elif ')
        complexity += code_snippet.count('while ')
        complexity += code_snippet.count('for ')
        complexity += code_snippet.count('and ')
        complexity += code_snippet.count('or ')
        features.append(complexity)
        
        # === VULNERABILITY PATTERNS (20 features) ===
        
        # SQL Injection indicators
        features.append(1 if re.search(r'execute\s*\(', code_snippet) else 0)
        features.append(1 if re.search(r'executemany\s*\(', code_snippet) else 0)
        features.append(1 if any(op in code_snippet for op in [' + ', ' % ', 'f"', '.format(']) else 0)
        features.append(1 if re.search(r'\?|%s|:\w+', code_snippet) else 0)  # Parameterization
        
        # Command Injection indicators
        features.append(1 if any(f in code_snippet for f in ['system', 'popen', 'exec', 'call']) else 0)
        features.append(1 if 'shell=True' in code_snippet else 0)
        features.append(1 if 'subprocess' in code_snippet else 0)
        features.append(1 if 'eval(' in code_snippet or 'exec(' in code_snippet else 0)
        
        # XSS indicators
        features.append(1 if 'innerHTML' in code_snippet else 0)
        features.append(1 if 'document.write' in code_snippet else 0)
        features.append(1 if 'render_template_string' in code_snippet else 0)
        features.append(1 if 'dangerouslySetInnerHTML' in code_snippet else 0)
        
        # Path Traversal indicators
        features.append(1 if 'open(' in code_snippet else 0)
        features.append(1 if 'os.path.join' in code_snippet else 0)
        features.append(1 if '..' in code_snippet else 0)
        
        # SSRF indicators
        features.append(1 if 'requests.' in code_snippet else 0)
        features.append(1 if 'urllib' in code_snippet else 0)
        features.append(1 if 'http://' in code_snippet or 'https://' in code_snippet else 0)
        
        # Deserialization indicators
        features.append(1 if 'pickle' in code_snippet else 0)
        features.append(1 if 'yaml.load' in code_snippet and 'yaml.safe_load' not in code_snippet else 0)
        
        # === CONTEXT FEATURES (15 features) ===
        
        # User input sources
        features.append(1 if any(src in code_snippet for src in ['request.', 'input(', 'sys.argv']) else 0)
        features.append(1 if 'request.GET' in code_snippet or 'request.POST' in code_snippet else 0)
        features.append(1 if 'request.args' in code_snippet or 'request.form' in code_snippet else 0)
        
        # Security measures
        features.append(1 if any(s in code_snippet for s in ['escape', 'sanitize', 'validate']) else 0)
        features.append(1 if 'csrf_token' in code_snippet or '@csrf_exempt' in code_snippet else 0)
        features.append(1 if 'authenticate' in code_snippet or 'login_required' in code_snippet else 0)
        
        # Dangerous keywords
        features.append(1 if 'password' in code_snippet.lower() else 0)
        features.append(1 if 'secret' in code_snippet.lower() else 0)
        features.append(1 if 'token' in code_snippet.lower() else 0)
        features.append(1 if 'api_key' in code_snippet.lower() else 0)
        
        # Framework indicators
        features.append(1 if 'django' in code_snippet.lower() else 0)
        features.append(1 if 'flask' in code_snippet.lower() else 0)
        features.append(1 if 'fastapi' in code_snippet.lower() else 0)
        
        # Error handling
        features.append(1 if code_snippet.count('try:') > 0 else 0)
        features.append(1 if code_snippet.count('except:') > code_snippet.count('except ') else 0)  # Bare except
        
        return np.array(features, dtype=np.float32)
    
    def train(self, training_data: List[Tuple[str, Dict, int]], 
             validation_split: float = 0.2):
        """
        Train classifier on labeled examples
        
        Args:
            training_data: List of (code_snippet, context, label)
                          where label is 1 for vulnerable, 0 for safe
            validation_split: Fraction of data for validation
        """
        if not LIGHTGBM_AVAILABLE:
            print("LightGBM not available. Cannot train model.")
            return {}
        
        print(f"Training on {len(training_data)} examples...")
        
        # Extract features
        X = []
        y = []
        
        for code, context, label in training_data:
            features = self.extract_features(code, context)
            X.append(features)
            y.append(label)
        
        X = np.array(X)
        y = np.array(y)
        
        # Split train/validation
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        # LightGBM parameters optimized for small datasets
        params = {
            'objective': 'binary',
            'metric': ['auc', 'binary_logloss'],
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.8,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'max_depth': 6,
            'min_data_in_leaf': 20,
            'verbose': -1,
        }
        
        # Create datasets
        train_data = lgb.Dataset(X_train, label=y_train)
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        
        # Train model
        callbacks = [
            lgb.early_stopping(stopping_rounds=10),
            lgb.log_evaluation(period=10)
        ]
        
        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=200,
            valid_sets=[train_data, val_data],
            valid_names=['train', 'valid'],
            callbacks=callbacks
        )
        
        # Evaluate
        y_pred = self.model.predict(X_val)
        y_pred_binary = (y_pred > 0.5).astype(int)
        
        try:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            accuracy = accuracy_score(y_val, y_pred_binary)
            precision = precision_score(y_val, y_pred_binary, zero_division=0)
            recall = recall_score(y_val, y_pred_binary, zero_division=0)
            f1 = f1_score(y_val, y_pred_binary, zero_division=0)
            
            print(f"\nValidation Results:")
            print(f"  Accuracy:  {accuracy:.3f}")
            print(f"  Precision: {precision:.3f}")
            print(f"  Recall:    {recall:.3f}")
            print(f"  F1 Score:  {f1:.3f}")
            
            metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
        except ImportError:
            print("scikit-learn not available for metrics")
            metrics = {}
        
        # Save model
        self.save_model()
        
        return metrics
    
    def predict(self, code_snippet: str, context: Dict = None) -> Tuple[bool, float]:
        """
        Predict if code is vulnerable
        
        Args:
            code_snippet: Code to analyze
            context: Additional context (file path, imports, etc.)
        
        Returns:
            (is_vulnerable, confidence_score)
        """
        # 1) Preferred path: Hugging Face classifier (UnixCoder / CodeBERT)
        if self.hf_classifier is not None and self.hf_classifier.is_ready:
            is_hf_vuln, hf_conf = self.hf_classifier.predict(code_snippet, context or {})
            # If HF is reasonably confident, trust its decision
            if hf_conf >= 0.5:
                return is_hf_vuln, hf_conf

        # 2) LightGBM model (if trained and available)
        if self.model is not None:
            features = self.extract_features(code_snippet, context)
            features = features.reshape(1, -1)
            probability = self.model.predict(features)[0]
            is_vulnerable = probability > 0.5
            return is_vulnerable, float(probability)

        # 3) Fallback heuristic if no ML model is available
        return self._rule_based_predict(code_snippet)
    
    def _rule_based_predict(self, code: str) -> Tuple[bool, float]:
        """Fallback rule-based prediction when model not available"""
        # Simple heuristic scoring
        score = 0.0
        
        # Check for dangerous patterns
        if re.search(r'execute\s*\([^)]*\+', code):
            score += 0.3
        if 'shell=True' in code:
            score += 0.3
        if 'eval(' in code or 'exec(' in code:
            score += 0.4
        if any(src in code for src in ['request.', 'input(', 'sys.argv']):
            score += 0.2
        
        # Reduce score for safety measures
        if any(s in code for s in ['escape', 'sanitize', 'validate']):
            score *= 0.5
        
        is_vulnerable = score > 0.5
        return is_vulnerable, min(score, 0.95)
    
    def save_model(self):
        """Save model and metadata to disk"""
        if not LIGHTGBM_AVAILABLE or self.model is None:
            return
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save LightGBM model
        model_file = self.model_path.with_suffix('.txt')
        self.model.save_model(str(model_file))
        
        # Save metadata
        metadata = {
            'version': '1.0',
            'num_features': 50,
            'model_type': 'lightgbm',
        }
        
        metadata_file = self.model_path.with_suffix('.json')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Model saved to {model_file}")
    
    def load_model(self):
        """Load model from disk"""
        if not LIGHTGBM_AVAILABLE:
            return
        
        model_file = self.model_path.with_suffix('.txt')
        
        if model_file.exists():
            try:
                self.model = lgb.Booster(model_file=str(model_file))
                print(f"Model loaded from {model_file}")
            except:
                print(f"Failed to load model from {model_file}")


# Training data generator
class TrainingDataGenerator:
    """Generate synthetic training data for vulnerability detection"""
    
    @staticmethod
    def generate_sql_injection_examples() -> List[Tuple[str, Dict, int]]:
        """Generate SQL injection training examples"""
        vulnerable = [
            ('cursor.execute("SELECT * FROM users WHERE id=" + user_id)', {}, 1),
            ('query = f"DELETE FROM items WHERE id={item_id}"\ndb.execute(query)', {}, 1),
            ('db.execute("UPDATE users SET name=\'%s\'" % request.GET.get("name"))', {}, 1),
            ('sql = "SELECT * FROM " + table_name + " WHERE id=" + str(id)\ncursor.execute(sql)', {}, 1),
            ('cursor.execute("SELECT * FROM users WHERE username=\'" + username + "\'")', {}, 1),
        ]
        
        safe = [
            ('cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))', {}, 0),
            ('cursor.execute("SELECT * FROM users WHERE id=%(id)s", {"id": user_id})', {}, 0),
            ('cursor.execute("SELECT * FROM users WHERE id=%s", [user_id])', {}, 0),
            ('cursor.execute("SELECT * FROM users WHERE id=1")', {}, 0),
            ('query = "SELECT * FROM users"\ncursor.execute(query)', {}, 0),
        ]
        
        return vulnerable + safe
    
    @staticmethod
    def generate_command_injection_examples() -> List[Tuple[str, Dict, int]]:
        """Generate command injection training examples"""
        vulnerable = [
            ('os.system("ls " + user_input)', {}, 1),
            ('subprocess.call("rm -rf " + path, shell=True)', {}, 1),
            ('eval(request.GET.get("code"))', {}, 1),
            ('exec(user_code)', {}, 1),
            ('os.popen("cat " + filename).read()', {}, 1),
        ]
        
        safe = [
            ('subprocess.call(["ls", directory])', {}, 0),
            ('subprocess.call(["rm", "-rf", path])', {}, 0),
            ('import shlex\nsubprocess.call(shlex.split(command))', {}, 0),
            ('subprocess.call("ls", shell=False)', {}, 0),
            ('result = some_function(user_input)', {}, 0),
        ]
        
        return vulnerable + safe
    
    @staticmethod
    def generate_xss_examples() -> List[Tuple[str, Dict, int]]:
        """Generate XSS training examples"""
        vulnerable = [
            ('return render_template_string("<h1>" + user_input + "</h1>")', {}, 1),
            ('element.innerHTML = request.args.get("name")', {}, 1),
            ('document.write(user_data)', {}, 1),
            ('return Response("<div>" + comment + "</div>")', {}, 1),
        ]
        
        safe = [
            ('from markupsafe import escape\nreturn f"<h1>{escape(user_input)}</h1>"', {}, 0),
            ('element.textContent = user_input', {}, 0),
            ('return render_template("index.html", name=user_input)', {}, 0),
            ('return jsonify({"data": user_input})', {}, 0),
        ]
        
        return vulnerable + safe
    
    @staticmethod
    def generate_all_examples() -> List[Tuple[str, Dict, int]]:
        """Generate complete training dataset"""
        examples = []
        examples.extend(TrainingDataGenerator.generate_sql_injection_examples())
        examples.extend(TrainingDataGenerator.generate_command_injection_examples())
        examples.extend(TrainingDataGenerator.generate_xss_examples())
        
        # Shuffle
        import random
        random.shuffle(examples)
        
        return examples


# CLI for training
if __name__ == '__main__':
    import sys
    
    classifier = VulnerabilityClassifier()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'train':
        # Generate training data
        print("Generating training data...")
        training_data = TrainingDataGenerator.generate_all_examples()
        print(f"Generated {len(training_data)} training examples")
        
        # Train model
        metrics = classifier.train(training_data)
        
    elif len(sys.argv) > 1 and sys.argv[1] == 'test':
        # Test prediction
        test_code = 'cursor.execute("SELECT * FROM users WHERE id=" + str(user_id))'
        is_vuln, conf = classifier.predict(test_code)
        print(f"Test: {test_code}")
        print(f"Vulnerable: {is_vuln}, Confidence: {conf:.2f}")
    
    else:
        print("Usage:")
        print("  python ml_classifier.py train    # Train new model")
        print("  python ml_classifier.py test     # Test prediction")

