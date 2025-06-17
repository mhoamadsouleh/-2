import telebot, os, subprocess, shutil, time, requests
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

token = '8067745587:AAEbeZ_vJOm9c-JVyKXFsaOlG0G7joYSVIQ'
ADMIN_ID = "6186106102"
SOLO = telebot.TeleBot(token)

UPLOAD_FOLDER = "./vps_upload_bot"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
uploaded_files = {}
user_uploads = {}
unlimited_users = set()
API_KEY = '2ec241972ed224405090681092436f106705ac33be3cd3b94d09d2725581891b'
url_scan = "https://www.virustotal.com/api/v3/files"
url_report = "https://www.virustotal.com/api/v3/analyses/"
headers = {"x-apikey": API_KEY}

def scan(file_path):
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(url_scan, headers=headers, files=files)

        if response.status_code == 200:
            scan_id = response.json()['data']['id']
            time.sleep(20)
            result_response = requests.get(f"{url_report}{scan_id}", headers=headers)
            if result_response.status_code == 200:
                result = result_response.json()['data']['attributes']
                return result['stats']['malicious'] == 0
            return False
        return False
    except:
        return False

@SOLO.message_handler(commands=['start'])
def send_welcome(message):
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("📂 رفع ملف", callback_data="upload_file"))
    keyboard.add(InlineKeyboardButton("📋 حالة البوت", callback_data="bot_status"))
    if str(message.from_user.id) == ADMIN_ID:
        keyboard.add(InlineKeyboardButton("🔧 لوحة تحكم المشرف", callback_data="admin_panel"))
    SOLO.send_message(message.chat.id, "مرحبًا بك! اختر أحد الخيارات:", reply_markup=keyboard)

@SOLO.callback_query_handler(func=lambda call: call.data == "upload_file")
def upload_prompt(call):
    SOLO.answer_callback_query(call.id)
    SOLO.send_message(call.message.chat.id, "📥 أرسل الملف الآن.")

@SOLO.message_handler(content_types=['document'])
def handle_file_upload(message):
    user_id = message.from_user.id
    file_info = SOLO.get_file(message.document.file_id)
    file_name = message.document.file_name
    if not file_name.endswith('.py'):
        SOLO.reply_to(message, "⚠️ فقط ملفات Python (.py) مسموحة!")
        return
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    downloaded_file = SOLO.download_file(file_info.file_path)
    with open(file_path, 'wb') as f:
        f.write(downloaded_file)
    SOLO.send_message(message.chat.id, "🔍 جاري فحص الملف...")
    if scan(file_path):
        uploaded_files[file_name] = {"path": file_path}
        SOLO.reply_to(message, "✅ الملف آمن وتم رفعه.")
    else:
        SOLO.reply_to(message, "❌ الملف يحتوي على أكواد خبيثة وتم رفضه.")

SOLO.infinity_polling()