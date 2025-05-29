import os
import json

# 設定你的圖片資料夾路徑和 JSON 檔案名稱
IMAGE_FOLDER = 'images'
DATA_JSON_FILE = 'data.json'

def generate_image_data():
    """
    掃描圖片資料夾，並根據現有 data.json 更新圖片資料。
    會保留現有圖片的 location, description, mapLink 資訊。
    """
    current_images_on_disk = set()
    new_data = []

    # 1. 掃描圖片資料夾中的所有圖片檔案
    if not os.path.exists(IMAGE_FOLDER):
        print(f"錯誤：找不到圖片資料夾 '{IMAGE_FOLDER}'。請確保它在同一個目錄中。")
        return

    for filename in sorted(os.listdir(IMAGE_FOLDER)):
        # 篩選出常見的圖片副檔名 (可以根據需要添加更多)
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif')):
            current_images_on_disk.add(filename)

    # 2. 讀取現有的 data.json 檔案
    existing_data = {}
    if os.path.exists(DATA_JSON_FILE):
        try:
            with open(DATA_JSON_FILE, 'r', encoding='utf-8') as f:
                data_from_json = json.load(f)
                for item in data_from_json:
                    # 從 src 路徑中提取檔名作為鍵
                    # 確保它能處理 'images/filename.jpg' 這樣的路徑
                    filename_from_src = os.path.basename(item.get('src', ''))
                    existing_data[filename_from_src] = item
            print(f"已讀取現有的 '{DATA_JSON_FILE}' 檔案。")
        except json.JSONDecodeError:
            print(f"警告：'{DATA_JSON_FILE}' 格式無效，將重新生成。")
        except Exception as e:
            print(f"警告：讀取 '{DATA_JSON_FILE}' 時發生錯誤: {e}，將重新生成。")

    # 3. 建立新的資料列表，保留現有資訊並添加新圖片
    for filename in sorted(list(current_images_on_disk)):
        src_path = os.path.join(IMAGE_FOLDER, filename).replace(os.sep, '/') # 確保路徑是斜線

        if filename in existing_data:
            # 如果圖片已存在於 JSON 中，保留其原有資料
            new_data.append(existing_data[filename])
        else:
            # 如果是新圖片，添加預設資訊
            new_data.append({
                "src": src_path,
                "alt": f"{filename.split('.')[0].replace('_', ' ').replace('-', ' ')}", # 從檔名自動生成 alt
                "location": "新圖片地點 (請修改)",
                "description": "這是新圖片的簡短描述 (請修改)",
                "mapLink": "https://maps.app.goo.gl/請貼上GoogleMap連結"
            })

    # 4. 將資料寫入 data.json 檔案
    try:
        with open(DATA_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=2) # indent=2 讓 JSON 易於閱讀
        print(f"'{DATA_JSON_FILE}' 已成功生成/更新。")
        print(f"共計 {len(new_data)} 張圖片。")
        print("請檢查 'data.json' 檔案，為新圖片填寫 'location', 'description' 和 'mapLink'。")
    except Exception as e:
        print(f"錯誤：寫入 '{DATA_JSON_FILE}' 時發生錯誤: {e}")

if __name__ == "__main__":
    generate_image_data()