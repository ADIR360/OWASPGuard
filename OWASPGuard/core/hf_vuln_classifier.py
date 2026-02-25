"""
Hugging Face based vulnerability classifier.

Integrates pretrained models like:
- mahdin70/unixcoder-code-vulnerability-detector
- mahdin70/codebert-devign-code-vulnerability-detector

These models are primarily trained on C/C++ (DetectVul/Devign),
but we expose a generic interface so they can be used as an
additional confidence signal alongside rule-based scanners.
"""

from typing import Tuple, Dict, Optional

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch

    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    AutoTokenizer = None  # type: ignore
    AutoModelForSequenceClassification = None  # type: ignore
    torch = None  # type: ignore


class HfVulnerabilityClassifier:
    """
    Wrapper around Hugging Face sequence classification models
    for code vulnerability detection.

    The interface matches the existing VulnerabilityClassifier.predict:
        predict(code_snippet, context) -> (is_vuln: bool, confidence: float)
    """

    # Default models suggested by the user (C/C++ focused)
    DEFAULT_MODELS = [
        "mahdin70/unixcoder-code-vulnerability-detector",
        "mahdin70/codebert-devign-code-vulnerability-detector",
    ]

    def __init__(
        self,
        model_name: Optional[str] = None,
        use_cuda: bool = False,
    ):
        self.model_name = model_name or self.DEFAULT_MODELS[0]
        self.use_cuda = use_cuda and HF_AVAILABLE and torch.cuda.is_available()
        self.tokenizer = None
        self.model = None

        if HF_AVAILABLE:
            try:
                self._load_model()
            except Exception:
                # If anything goes wrong, we simply stay in "disabled" mode
                self.tokenizer = None
                self.model = None

    def _load_model(self) -> None:
        """Load tokenizer and model from Hugging Face."""
        # trust_remote_code=False for safety
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            trust_remote_code=False,
        )
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            trust_remote_code=False,
        )

        if self.use_cuda:
            self.model.to("cuda")  # type: ignore

        # Put model in eval mode
        self.model.eval()  # type: ignore

    @property
    def is_ready(self) -> bool:
        """Return True if HF model is available and loaded."""
        return HF_AVAILABLE and self.tokenizer is not None and self.model is not None

    def predict(self, code_snippet: str, context: Dict = None) -> Tuple[bool, float]:
        """
        Predict if a code snippet is vulnerable.

        Returns:
            (is_vulnerable, confidence_score 0.0-1.0)
        """
        if not self.is_ready or not code_snippet.strip():
            # Not available – caller should treat this as "no signal"
            return False, 0.0

        try:
            # Tokenize
            inputs = self.tokenizer(  # type: ignore
                code_snippet,
                return_tensors="pt",
                truncation=True,
                padding="max_length",
                max_length=512,
            )

            if self.use_cuda:
                inputs = {k: v.to("cuda") for k, v in inputs.items()}

            with torch.no_grad():  # type: ignore
                outputs = self.model(**inputs)  # type: ignore
                logits = outputs.logits
                probs = torch.nn.functional.softmax(logits, dim=-1)  # type: ignore

            # Assumption: label 1 == vulnerable, label 0 == safe
            vulnerable_prob = float(probs[0, 1].item())
            is_vulnerable = vulnerable_prob >= 0.5

            return is_vulnerable, vulnerable_prob

        except Exception:
            # On any error, fail safe and return no decision
            return False, 0.0

