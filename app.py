import os
import json
from flask import Flask, jsonify, request, redirect, url_for, session, render_template 
from flask_cors import CORS
import requests
import base64 
from functools import wraps 

# --- GitHub OAuth 憑證 ---
GITHUB_CLIENT_ID = "Ov23liq5qoBSni6pEp13"     
GITHUB_CLIENT_SECRET = "8e92d5f32c8fab3dec2623ca0ff941a3bfb0ce70" 

# --- GitHub 倉庫資訊 ---
GITHUB_REPO_OWNER = "LKH098" 
GITHUB_REPO_NAME = "my-travel-photos-site" 
GITHUB_BRANCH = "main" 

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:8000", "http://localhost:8000"])

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_super_secret_random_key_for_flask_session_security_12345_CHANGE_ME_PLEASE')

def login_required(f):
    @wraps(f) 
    def decorated_function(*args, **kwargs):
        if 'github_access_token' not in session:
            print("裝飾器：偵測到未授權的訪問。")
            return jsonify({"status": "error", "message": "未授權：需要登入"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def hello_world():
    return "你好，這是您的 Flask 後端服務！"

@app.route('/login/github')
def login_github():
    redirect_uri = url_for('github_callback', _external=True)
    # --- 重要：調試403錯誤的關鍵 ---
    print("="*50)
    print("正在準備導向 GitHub 進行 OAuth 授權...")
    print(f"1. 您的 GitHub Client ID: {GITHUB_CLIENT_ID}")
    print(f"2. Flask 產生的回呼 URL (redirect_uri): {redirect_uri}")
    print("3. 請「非常仔細地」確認，上述 redirect_uri 與您在 GitHub OAuth App 設定中的")
    print(f"   'Authorization callback URL' **完全一致**。")
    print(f"   您的 GitHub OAuth App 設定連結: https://github.com/settings/applications (找到 Client ID 為 {GITHUB_CLIENT_ID} 的應用)")
    print("   常見錯誤：http vs https, localhost vs 127.0.0.1, 尾部斜線, 埠號不匹配。")
    print("="*50)

    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"scope=repo&"  
        f"redirect_uri={redirect_uri}"
    )
    return redirect(github_auth_url)

@app.route('/callback')
def github_callback():
    # --- 重要：調試403錯誤的關鍵 ---
    print("="*50)
    print("已從 GitHub 重定向回 /callback 路由。")
    print(f"1. 瀏覽器請求的完整 URL (由 GitHub 重定向過來): {request.url}")
    print(f"2. Flask 內部認為的回呼 URL (用於交換 token): {url_for('github_callback', _external=True)}")
    print("   請再次確認，步驟 2 的 URL 是否與您在 GitHub OAuth App 設定中的 'Authorization callback URL' 完全一致。")
    print("="*50)

    code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    error_uri = request.args.get('error_uri')


    if error:
        print(f"GitHub OAuth 錯誤：{error} - {error_description}")
        print(f"錯誤相關 URI: {error_uri}")
        # 針對 redirect_uri_mismatch 提供更明確的提示
        if error == "redirect_uri_mismatch":
            return jsonify({
                "status": "error", 
                "message": "GitHub 授權失敗：重新導向 URI 不匹配 (redirect_uri_mismatch)。",
                "details": f"GitHub 報告的錯誤為：{error_description}. 請檢查您在 GitHub OAuth App 設定中的 'Authorization callback URL' 是否與您的應用程式請求的 ({url_for('github_callback', _external=True)}) 完全一致。"
            }), 400
        return jsonify({"status": "error", "message": f"GitHub 授權失敗：{error_description} ({error})"}), 400
    
    if not code:
        return jsonify({"status": "error", "message": "GitHub 授權失敗：未收到授權碼"}), 400

    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": url_for('github_callback', _external=True) 
    }
    print(f"準備向 GitHub 交換 token，使用的 redirect_uri: {data['redirect_uri']}")

    try:
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status() 
        token_info = response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"獲取 Access Token 時發生 HTTP 錯誤: {http_err}")
        print(f"GitHub 回應狀態碼: {response.status_code}")
        print(f"GitHub 回應內容: {response.text}")
        if response.status_code == 403: # 通常不是在交換 token 時的 403，而是在 redirect_uri 不匹配時 GitHub 在 callback 前就可能阻擋
             return jsonify({"status": "error", "message": "無法獲取 Access Token：GitHub 返回 403 Forbidden。極有可能是 Client ID/Secret 或回呼 URL 問題。"}), 403
        return jsonify({"status": "error", "message": f"無法獲取 Access Token: {http_err}", "details": response.text}), response.status_code
    except requests.exceptions.RequestException as e:
        print(f"獲取 Access Token 時發生網路錯誤: {e}")
        return jsonify({"status": "error", "message": f"與 GitHub 通訊時發生網路錯誤: {e}"}), 500
    
    access_token = token_info.get('access_token')
    if not access_token:
        print(f"未能獲取 Access Token。GitHub 返回: {token_info}")
        return jsonify({"status": "error", "message": "未能獲取 Access Token", "details": token_info}), 400

    session['github_access_token'] = access_token
    print("成功獲取 Access Token 並存入 session。")

    frontend_url = os.environ.get('FRONTEND_URL', 'http://127.0.0.1:8000')
    return redirect(f"{frontend_url}?login_success=true&from_callback=true")


@app.route('/api/auth_status')
def auth_status():
    if 'github_access_token' in session:
        access_token = session['github_access_token']
        headers = {"Authorization": f"token {access_token}"}
        user_api_url = "https://api.github.com/user"
        
        try:
            user_response = requests.get(user_api_url, headers=headers, timeout=5) 
            if user_response.status_code == 200:
                user_info = user_response.json()
                return jsonify({"is_logged_in": True, "username": user_info.get('login'), "avatar_url": user_info.get('avatar_url')}), 200
            elif user_response.status_code == 401: 
                print("Access Token 無效或過期 (來自 /api/auth_status)，清除 session。")
                session.pop('github_access_token', None)
                return jsonify({"is_logged_in": False, "message": "Access Token 無效或過期，請重新登入"}), 200
            else:
                print(f"獲取 GitHub 用戶資訊失敗，狀態碼: {user_response.status_code}, 回應: {user_response.text}")
                return jsonify({"is_logged_in": True, "message": "無法驗證 GitHub 用戶資訊，但 Token 存在"}), 200 
        except requests.exceptions.Timeout:
            print("獲取 GitHub 用戶資訊時請求超時。")
            return jsonify({"is_logged_in": False, "message": "網路請求超時，無法驗證登入狀態"}), 500 
        except requests.exceptions.RequestException as e:
            print(f"獲取 GitHub 用戶資訊時網路錯誤: {e}")
            return jsonify({"is_logged_in": False, "message": f"網路錯誤，無法驗證登入狀態: {e}"}), 500
    else:
        return jsonify({"is_logged_in": False}), 200

@app.route('/api/logout', methods=['POST', 'GET']) 
def logout_user():
    session.pop('github_access_token', None) 
    session.clear() 
    print("使用者已登出，session 已清除。")
    return jsonify({"status": "success", "message": "已成功登出"}), 200

@app.route('/api/update-data-json', methods=['POST'])
@login_required 
def update_data_json_to_github():
    access_token = session.get('github_access_token')
    if not access_token: 
         return jsonify({"status": "error", "message": "未授權：請先登入 (update_data_json)"}), 401

    if not request.is_json:
        return jsonify({"status": "error", "message": "請求必須是 JSON 格式"}), 400

    try:
        new_data_content = request.get_json()
        if 'items' not in new_data_content or not isinstance(new_data_content['items'], list):
            return jsonify({"status": "error", "message": "請求的 JSON 格式無效，缺少 'items' 列表"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"解析 JSON 請求時發生錯誤: {e}"}), 400
        
    file_path = "data.json" 

    get_file_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/contents/{file_path}?ref={GITHUB_BRANCH}"
    headers_get_put = { 
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    file_sha = None 
    try:
        print(f"正在獲取 {file_path} 的 SHA...")
        get_response = requests.get(get_file_url, headers=headers_get_put, timeout=10)
        if get_response.status_code == 200:
            file_sha = get_response.json().get('sha')
            print(f"成功獲取 SHA: {file_sha}")
        elif get_response.status_code == 404:
            print(f"{file_path} 在倉庫中不存在，將會創建新檔案。")
            file_sha = None 
        elif get_response.status_code == 401:
             print(f"獲取 {file_path} SHA 時發生授權錯誤 (401)。")
             session.pop('github_access_token', None) 
             return jsonify({"status": "error", "message": "授權失敗或 Token 過期，無法獲取檔案 SHA。請重新登入。"}), 401
        else:
            print(f"無法獲取 {file_path} 的 SHA，狀態碼: {get_response.status_code}, 回應: {get_response.text}")
            return jsonify({"status": "error", "message": f"無法獲取 {file_path} 的 SHA，GitHub 返回錯誤。", "details": get_response.json() if get_response.content else get_response.text}), get_response.status_code
    except requests.exceptions.Timeout:
        print(f"獲取 {file_path} SHA 時請求超時。")
        return jsonify({"status": "error", "message": "網路請求超時，無法獲取檔案 SHA"}), 500
    except requests.exceptions.RequestException as e:
        print(f"獲取 {file_path} SHA 時網路錯誤: {e}")
        return jsonify({"status": "error", "message": f"網路錯誤，無法獲取檔案 SHA: {e}"}), 500

    try:
        updated_content_str = json.dumps(new_data_content, ensure_ascii=False, indent=2)
        updated_content_base64 = base64.b64encode(updated_content_str.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"轉換 JSON 或 Base64 編碼時發生錯誤: {e}")
        return jsonify({"status": "error", "message": f"處理提交內容時發生錯誤: {e}"}), 500

    commit_message = f"經由網站後台更新 {file_path}"
    commit_data = {
        "message": commit_message,
        "content": updated_content_base64,
        "branch": GITHUB_BRANCH
    }
    if file_sha: 
        commit_data["sha"] = file_sha

    update_file_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/contents/{file_path}"
    
    try:
        print(f"正在提交更新到 {file_path}...")
        put_response = requests.put(update_file_url, headers=headers_get_put, json=commit_data, timeout=15)
        if put_response.status_code in [200, 201]: 
            commit_url = put_response.json().get("commit", {}).get("html_url", "N/A")
            print(f"成功提交 {file_path} 到 GitHub。Commit URL: {commit_url}")
            return jsonify({"status": "success", "message": f"{file_path} 已成功更新到 GitHub", "commit_details": put_response.json()}), put_response.status_code
        elif put_response.status_code == 401: 
             print(f"提交 {file_path} 時發生授權錯誤 (401)。")
             session.pop('github_access_token', None) 
             return jsonify({"status": "error", "message": "授權失敗或 Token 過期，無法更新檔案。請重新登入。"}), 401
        elif put_response.status_code == 409: 
             print(f"提交 {file_path} 時發生衝突 (409)。可能是檔案已被其他人修改。")
             return jsonify({"status": "error", "message": f"更新 {file_path} 失敗：檔案衝突，可能已被其他人修改。請重新整理頁面後再試。"}), 409
        else:
            print(f"無法提交 {file_path} 到 GitHub，狀態碼: {put_response.status_code}, 回應: {put_response.text}")
            return jsonify({"status": "error", "message": f"無法提交 {file_path} 到 GitHub", "details": put_response.json() if put_response.content else put_response.text}), put_response.status_code
    except requests.exceptions.Timeout:
        print(f"提交 {file_path} 時請求超時。")
        return jsonify({"status": "error", "message": "網路請求超時，無法提交檔案"}), 500
    except requests.exceptions.RequestException as e:
        print(f"提交 {file_path} 時網路錯誤: {e}")
        return jsonify({"status": "error", "message": f"網路錯誤，無法提交檔案: {e}"}), 500

if __name__ == '__main__':
    print("後端 Flask 服務正在啟動...")
    app.run(host='0.0.0.0', port=5000, debug=True)
