import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib

# خواندن دیتاست پاک‌سازی‌شده
df = pd.read_csv("final_dataset_clean.csv")
X = df.drop("Label", axis=1)
y = df["Label"]

# تقسیم Train/Test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# تعریف مدل‌ها
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Random Forest": RandomForestClassifier(n_estimators=100),
    "SVM": SVC(),
    "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric="logloss"),
    "Neural Network": MLPClassifier(max_iter=1000)
}

# آموزش، تست و ذخیره همه مدل‌ها
for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n{name}")
    print("Accuracy:", acc)
    print("Confusion Matrix:\n", cm)

    # ذخیره مدل با نام مناسب
    filename = name.lower().replace(" ", "_") + "_model.pkl"
    joblib.dump(model, filename)
    print(f"✅ Model saved as {filename}")
