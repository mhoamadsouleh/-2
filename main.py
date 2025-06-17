import telebot, os, subprocess, shutil, time, requests
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

token = os.getenv("TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID")
API_KEY = os.getenv("VT_API_KEY")

SOLO = telebot.TeleBot(token)

UPLOAD_FOLDER = "./vps_upload_bot"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
uploaded_files = {}
user_uploads = {}
unlimited_users = set()

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
            time.sleep(15)
            result_response = requests.get(f"{url_report}{scan_id}", headers=headers)
            if result_response.status_code == 200:
                result = result_response.json()['data']['attributes']
                return result['stats']['malicious'] == 0
            else:
                return False
        else:
            return False
    except Exception as e:
        print(f"Scan error: {e}")
        return False

@SOLO.message_handler(commands=['start'])
def start_handler(message):
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("📂 رفع ملف", callback_data="upload_file"))
    keyboard.add(InlineKeyboardButton("📋 حالة البوت", callback_data="bot_status"))
    if str(message.from_user.id) == ADMIN_ID:
        keyboard.add(InlineKeyboardButton("🔧 لوحة تحكم", callback_data="admin_panel"))
    SOLO.send_message(message.chat.id, "مرحبًا بك في بوت الاستضافة! اختر:", reply_markup=keyboard)

@SOLO.callback_query_handler(func=lambda call: call.data == "upload_file")
def ask_for_file(call):
    SOLO.send_message(call.message.chat.id, "📥 أرسل الآن ملف `.py` الخاص بك.")

@SOLO.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    file_info = SOLO.get_file(message.document.file_id)
    file_name = message.document.file_name

    if not file_name.endswith(".py"):
        return SOLO.reply_to(message, "⚠️ فقط ملفات Python مدعومة!")

    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    downloaded_file = SOLO.download_file(file_info.file_path)
    with open(file_path, 'wb') as f:
        f.write(downloaded_file)

    SOLO.send_message(message.chat.id, "🔍 جاري الفحص عبر VirusTotal...")
    if not scan(file_path):
        return SOLO.send_message(message.chat.id, "⚠️ الملف مشبوه وتم رفضه.")

    uploaded_files[file_name] = {
        "path": file_path,
        "status": "مرفوع",
        "user_id": user_id
    }

    keyboard = InlineKeyboardMarkup()
    keyboard.add(
        InlineKeyboardButton("▶️ تشغيل", callback_data=f"run_{file_name}"),
        InlineKeyboardButton("🛑 إيقاف", callback_data=f"stop_{file_name}"),
        InlineKeyboardButton("🗑️ حذف", callback_data=f"delete_{file_name}")
    )

    SOLO.send_message(message.chat.id, "✅ الملف آمن وتم رفعه.", reply_markup=keyboard)

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("run_"))
def run_file(call):
    file_name = call.data.replace("run_", "")
    file_data = uploaded_files.get(file_name)
    if not file_data:
        return SOLO.answer_callback_query(call.id, "❌ الملف غير موجود.")
    
    try:
        proc = subprocess.Popen(["python3", file_data["path"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        uploaded_files[file_name]["process"] = proc
        uploaded_files[file_name]["status"] = "يعمل"
        SOLO.send_message(call.message.chat.id, f"✅ تم تشغيل: {file_name}")
    except Exception as e:
        SOLO.send_message(call.message.chat.id, f"⚠️ خطأ: {e}")

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("stop_"))
def stop_file(call):
    file_name = call.data.replace("stop_", "")
    proc = uploaded_files.get(file_name, {}).get("process")
    if proc:
        proc.terminate()
        uploaded_files[file_name]["status"] = "موقوف"
        SOLO.send_message(call.message.chat.id, f"🛑 تم إيقاف: {file_name}")
    else:
        SOLO.send_message(call.message.chat.id, "⚠️ لا يوجد عملية قيد التشغيل.")

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("delete_"))
def delete_file(call):
    file_name = call.data.replace("delete_", "")
    file_data = uploaded_files.pop(file_name, None)
    if file_data and os.path.exists(file_data["path"]):
        os.remove(file_data["path"])
    SOLO.send_message(call.message.chat.id, f"🗑️ تم حذف الملف: {file_name}")

SOLO.infinity_polling()
