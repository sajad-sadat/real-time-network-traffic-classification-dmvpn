import pandas as pd
import glob
import os

# مسیر پوشه‌ای که همه CSVها داخلش هست
path = "/home/sajadsadat/Desktop/New Folder/my-dataset/"
all_files = glob.glob(os.path.join(path, "*.csv"))

print("Found files:", all_files)  # لیست فایل‌ها برای اطمینان

if not all_files:
    print("No CSV files found in the folder. Check the path again.")
else:
    # خواندن و ترکیب همه CSVها
    df_list = [pd.read_csv(f) for f in all_files]
    combined_df = pd.concat(df_list, ignore_index=True)

    # ذخیره دیتاست نهایی
    combined_df.to_csv("final_dataset.csv", index=False)
    print("Final dataset created with shape:", combined_df.shape)
