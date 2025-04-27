import torch
from transformers import BertModel
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from pymorphy3 import MorphAnalyzer
import re
import numpy as np
import nltk
from typing import List

# Инициализация NLTK
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

class ToxicityClassifier:
    def __init__(self, model_path: str):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self._load_model(model_path)
        self._init_text_processing()

    def _load_model(self, model_path: str):
        checkpoint = torch.load(model_path, map_location=self.device, weights_only=False)
        self.clf = checkpoint['classifier']
        self.bert_model = BertModel.from_pretrained('DeepPavlov/rubert-base-cased')
        self.bert_model.load_state_dict(checkpoint['bert_state_dict'])
        self.tokenizer = checkpoint['tokenizer']
        self.params = checkpoint['model_params']
        self.bert_model = self.bert_model.to(self.device)

    def _init_text_processing(self):
        self.morph = MorphAnalyzer()
        self.custom_stopwords = set(stopwords.words('russian')) - {
            'не', 'ни', 'нет', 'никогда', 'никуда', 'никак', 'ничего',
            'да', 'очень', 'больше', 'хорошо', 'плохо', 'просто', 'ведь'
        }

    def predict_toxicity(self, text: str) -> tuple[bool, float]:
        """Возвращает (is_toxic, probability) для одного текста"""
        predictions, probas = self.predict([text])
        return bool(predictions[0]), float(probas[0])

    def predict(self, texts: List[str]):
        processed_texts = [self.preprocess_text(t) for t in texts]
        embeddings = self._get_embeddings(processed_texts)
        probas = self.clf.predict_proba(embeddings)[:, 1]
        predictions = (probas > self.params['threshold']).astype(int)
        return predictions, probas

    def _get_embeddings(self, texts: List[str]):
        self.bert_model.eval()
        embeddings = []
        for i in range(0, len(texts), self.params['batch_size']):
            batch = texts[i:i + self.params['batch_size']]
            inputs = self.tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=self.params['max_length'],
                return_tensors="pt"
            ).to(self.device)
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
            embeddings.append(outputs.last_hidden_state[:, 0, :].cpu().numpy())
        return np.concatenate(embeddings, axis=0)

    def preprocess_text(self, text: str):
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'\d+', '', text.lower())
        text = re.sub(r'[^а-яё!?*#\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        text = re.sub(r'(.)\1{3,}', r'\1\1\1', text)

        words = word_tokenize(text, language='russian')
        processed = []
        for word in words:
            if word in {'!', '?', '?!', '!?'}:
                processed.append(word)
                continue
            if word in self.custom_stopwords:
                continue
            parsed = self.morph.parse(word)[0]
            if any(tag in parsed.tag for tag in {'INTJ', 'PRCL', 'NPRO'}):
                processed.append(word)
            else:
                processed.append(parsed.normal_form)
        return ' '.join(processed).replace('не ', 'не_')

# Инициализация классификатора при импорте
from config import MODEL_PATH
toxicity_classifier = ToxicityClassifier(MODEL_PATH)
