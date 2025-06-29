import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, ConcatDataset
import pandas as pd
import numpy as np
from matplotlib import pyplot as plt
import os
import json
import logging
from model import LSTMClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    log_loss,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
import time


DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# TRAIN_FEATURES = ['Dst Port', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets','Total Length of Fwd Packet', 'Total Length of Bwd Packet','Fwd Packet Length Max', 'Fwd Packet Length Min','Fwd Packet Length Mean', 'Fwd Packet Length Std','Bwd Packet Length Max', 'Bwd Packet Length Min','Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s','Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max','Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std','Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean','Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags','Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length','Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s','Packet Length Min', 'Packet Length Max', 'Packet Length Mean','Packet Length Std', 'Packet Length Variance', 'FIN Flag Count','SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count','URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio','Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg','Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg','Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg','Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets','Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Bwd Init Win Bytes','Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std','Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max','Idle Min', 'Label']
TRAIN_FEATURES = ["Dst Port", "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label",]

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(message)s'
)


class TimeSeriesDataset(Dataset):
    def __init__(self, X, y, sequence_length=10):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)
        self.sequence_length = sequence_length

    def __len__(self):
        return len(self.X) - self.sequence_length + 1

    def __getitem__(self, idx):
        x_seq = self.X[idx:idx+self.sequence_length]
        y_seq = self.y[idx+self.sequence_length - 1]
        return x_seq, y_seq


def create_data_loaders(X, y, batch_size=32, sequence_length=10):
    """Create train, validation, and test data loaders"""
    # Convert pandas DataFrames to numpy arrays
    if hasattr(X, 'values'):
        X = X.values
    if hasattr(y, 'values'):
        y = np.zeros(len(y))

    dataset = TimeSeriesDataset(X, y, sequence_length)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

    return loader


def predict_model(model, data_loader, device):
    """Evaluate model on given data loader"""
    model.eval()
    with torch.no_grad():
        for x, y in data_loader:
            x = x.to(device)
            y_pred = model(x)
            probs = torch.exp(y_pred)
            _, predicted = torch.max(y_pred, 1)
            predicted = predicted.cpu().numpy()
            return predicted


def main():
    model = LSTMClassifier(input_dim=77, hidden_dim=128, output_dim=2).to(DEVICE)
    model_path = '/usr/local/flexric/xApp/python3/near-rt-ric/custom-xapp/LSTM_model/best_model.pth'
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))

    flow_data_path = '/tmp/measurements_data/measurements.csv'
    while True:
        time.sleep(0.5)  # Wait for 10 seconds before checking the file again
        logging.info("Starting inference loop...")

        try:
            df = pd.read_csv(flow_data_path) #, header=None
            if len(df) < 2:
                logging.error("The CSV file is empty or does not contain enough data.")
                continue
        except:
            logging.error(f"Error reading the CSV file at {flow_data_path}. Please check the file path and format.")
            continue


        # pred_df = df.iloc[:, 1:]
        pred_df = df[TRAIN_FEATURES].copy()
        
        X, y = pred_df.iloc[:, :-1], pred_df.iloc[:, -1]
        scaler = StandardScaler()
        X = scaler.fit_transform(X)

        sequence_length = 5
        if len(X) < sequence_length:
            logging.error("Insufficient data for the specified sequence length.")
            continue

        logging.info(f"Starting inference with sequence length: {sequence_length}")
        data_loader = create_data_loaders(X, y, batch_size=len(X), sequence_length=sequence_length)

        pred = predict_model(model, data_loader, DEVICE)
        df_pred_1 = df[(sequence_length-1):][(pred == 1)]
        try:
            pred = df_pred_1["Src IP"].value_counts().to_dict()
            malicious_ip = [ip for ip, count in pred.items() if count > 5]
            
            with open("/usr/local/flexric/xApp/python3/near-rt-ric/malicious_ip.json", "w") as f:
                json.dump(malicious_ip, f, indent=4)
            logging.info(f"Malicious IPs {pred}")
        except:
            logging.error("Error in processing predictions or saving to JSON file.")

if __name__ == "__main__":
    main()