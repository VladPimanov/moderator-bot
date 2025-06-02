import torch
from transformers import BertModel, BertTokenizer, BertConfig
import numpy as np
from typing import List, Tuple
import os
import logging
from sklearn.linear_model import LogisticRegression
import torch.serialization

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Разрешаем загрузку scikit-learn моделей
torch.serialization.add_safe_globals([LogisticRegression])

class ToxicityClassifier:
    def __init__(self, model_path: str):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {self.device}")
        
        if not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        self._load_model(model_path)
        self._init_tokenizer()
        logger.info("Toxicity classifier initialized successfully")

    def _load_model(self, model_path: str) -> None:
        """Загрузка модели и весов из файла"""
        try:
            checkpoint = torch.load(model_path, map_location=self.device, weights_only=False)
            
            # Инициализация BERT
            config = BertConfig.from_pretrained('DeepPavlov/rubert-base-cased')
            self.bert_model = BertModel(config)
            
            # Загрузка весов BERT
            state_dict = checkpoint.get('bert_state_dict', {})
            self.bert_model.load_state_dict(state_dict, strict=False)
            
            # Загрузка классификатора
            self.clf = checkpoint.get('classifier')
            if self.clf is None:
                raise ValueError("Classifier not found in checkpoint")
            
            # Параметры модели
            self.params = checkpoint.get('model_params', {
                'threshold': 0.7,
                'max_length': 512,
                'batch_size': 8
            })
            
            self.bert_model = self.bert_model.to(self.device)
            logger.info("BERT model and classifier loaded successfully")
            
        except Exception as e:
            logger.error(f"Model loading error: {str(e)}")
            raise RuntimeError(f"Model loading error: {str(e)}")

    def _init_tokenizer(self) -> None:
        """Инициализация токенизатора"""
        try:
            self.tokenizer = BertTokenizer.from_pretrained(
                'DeepPavlov/rubert-base-cased',
                do_lower_case=False,
                padding_side='right'
            )
            
            # Гарантируем наличие специальных токенов
            if self.tokenizer.pad_token is None:
                self.tokenizer.add_special_tokens({'pad_token': '[PAD]'})
            if self.tokenizer.unk_token is None:
                self.tokenizer.add_special_tokens({'unk_token': '[UNK]'})
                
            logger.info("Tokenizer initialized successfully")
        except Exception as e:
            logger.error(f"Tokenizer initialization error: {str(e)}")
            raise RuntimeError(f"Tokenizer initialization error: {str(e)}")

    def predict_toxicity(self, text: str) -> Tuple[bool, float]:
        """
        Предсказание токсичности для одного текста
        
        Args:
            text (str): Текст для анализа
            
        Returns:
            Tuple[bool, float]: (is_toxic, probability)
        """
        try:
            predictions, probas = self.predict([text])
            return bool(predictions[0]), float(probas[0])
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return False, 0.0

    def predict(self, texts: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Пакетное предсказание токсичности
        
        Args:
            texts (List[str]): Список текстов для анализа
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: (predictions, probabilities)
        """
        try:
            embeddings = self._get_embeddings(texts)
            if len(embeddings) == 0:
                return np.array([]), np.array([])
                
            probas = self.clf.predict_proba(embeddings)[:, 1]
            predictions = (probas > self.params['threshold']).astype(int)
            return predictions, probas
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return np.array([]), np.array([])

    def _get_embeddings(self, texts: List[str]) -> np.ndarray:
        """Получение эмбеддингов для списка текстов"""
        self.bert_model.eval()
        embeddings = []
        
        batch_size = self.params.get('batch_size', 8)
        max_length = self.params.get('max_length', 512)
        
        i = 0
        while i < len(texts):
            batch = texts[i:i + batch_size]
            
            try:
                inputs = self.tokenizer(
                    batch,
                    padding=True,
                    truncation=True,
                    max_length=max_length,
                    return_tensors="pt"
                ).to(self.device)
                
                with torch.no_grad():
                    outputs = self.bert_model(**inputs)
                
                batch_embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
                embeddings.append(batch_embeddings)
                i += batch_size
                
            except RuntimeError as e:
                if "CUDA out of memory" in str(e) and batch_size > 1:
                    batch_size = max(1, batch_size // 2)
                    logger.warning(f"GPU memory error, reducing batch size to {batch_size}")
                    continue
                logger.error(f"Batch processing error: {str(e)}")
                i += batch_size
            except Exception as e:
                logger.error(f"Batch processing error: {str(e)}")
                i += batch_size
                
        return np.concatenate(embeddings, axis=0) if embeddings else np.array([])

# Инициализация классификатора
try:
    from config import Config
    toxicity_classifier = ToxicityClassifier(Config.MODEL_PATH)
    logger.info("Moderation service initialized successfully")
except ImportError as e:
    logger.error("Error: Config module not found")
    toxicity_classifier = None
except Exception as e:
    logger.error(f"Classifier initialization error: {str(e)}")
    toxicity_classifier = None