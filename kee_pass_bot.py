import logging
import operator
import random

from pykeepass.exceptions import CredentialsError
from telegram import Update, Bot, ParseMode
from telegram.ext import Updater, CommandHandler, Filters, CallbackContext, MessageHandler
from hashlib import sha3_256
import json
import os.path
import time
from pykeepass import PyKeePass
import os
from pysondb import db
import secrets
import string
from PIL import Image
from pyzbar import pyzbar
import pyotp
import io
import threading

def str_hash(s: str) -> str:
    return sha3_256((config['salt'] + s + config['salt']).encode('utf-8')).hexdigest()

def user_id_hash(user_id: int) -> str:
    return str_hash(str(user_id))

def rand_password(size: int) -> str:
    return ''.join(secrets.choice(string.printable) for _ in range(size))

def set_user_data(user: str, fake_master_password: str, trusted_user_ids: list):
    trusted_users = [user_id_hash(id) for id in trusted_user_ids]
    new_data = {"user": user, "fake_master_password": str_hash(fake_master_password), "trusted_user": trusted_users}
    users = users_db.getByQuery({"user": user})
    if len(users) == 0:
        users_db.add(new_data)
    else:
        users_db.updateByQuery(users[0], new_data)

def check_message_deleting():
    while True:
        time.sleep(0.2)
        with delete_message_queue_lock:
            if not updater.running:
                for item in delete_message_queue:
                    try:
                        item['message'].delete()
                    except Exception as ex:
                        log.exception("exception")
                break
            else:
                if delete_message_queue:
                    item = delete_message_queue[0]
                    if time.time() >= item['time']:
                        try:
                            item['message'].delete()
                        except Exception as ex:
                            log.exception("exception")
                        delete_message_queue.pop(0)
                        if item['user'] in incorrect_delete_message_queue:
                            for msg in incorrect_delete_message_queue[item['user']]:
                                try:
                                    msg.delete()
                                except Exception as ex:
                                    log.exception("exception")
                                incorrect_delete_message_queue[item['user']].remove(msg)


def add_message_to_delete(message, user: str, delay=None):
    if not message:
        return
    with delete_message_queue_lock:
        if user in incorrect_delete_message_queue and message in incorrect_delete_message_queue[user]:
            incorrect_delete_message_queue[user].remove(message)
        if not delay:
            delay = int(config['delete_message_delay'])
        delete_message_queue.append({'message': message, 'user': user, 'time': time.time() + delay})

def add_incorrect_message_to_delete(message, user: str):
    if not message:
        return
    with delete_message_queue_lock:
        if user not in incorrect_delete_message_queue:
            incorrect_delete_message_queue[user] = list()
        incorrect_delete_message_queue[user].append(message)

def remove(path: str):
    if 'remove_cmd' in config:
        os.system(config['remove_cmd'] + ' ' + path)
    else:
        os.remove(path)

def decode_qr(image_data):
    image = Image.open(io.BytesIO(image_data))
    return pyzbar.decode(image)

def parse_totp(data):
    totp = pyotp.parse_uri(data)
    username = totp.name if totp.name != totp.issuer else None
    return totp.issuer, username, totp.secret

def create_db(user: str, password: str, fake_master_password: str, trusted_user_ids: list):
    filename = user + '.kdbx'
    if os.path.isfile(filename):
        remove(filename)
    env = os.environ.copy()
    os.environ['TERM'] = "xterm-256color"
    os.system(f'printf "{password}\n{password}\n" | kpcli --command "saveas {filename}"')
    os.environ = env
    time.sleep(3)
    set_user_data(user, fake_master_password, trusted_user_ids)

def get_db(user: str, password: str) -> PyKeePass:
    users = users_db.getByQuery({"user": user})
    if len(users) == 1:
        if users[0]["fake_master_password"] == str_hash(password):
            new_fake_password = rand_password(len(password))
            new_trusted_user_id = str(random.randint(100_000_000, 500_000_000))
            create_db(user, password, new_fake_password, [new_trusted_user_id])
    try:
        return PyKeePass(user + '.kdbx', password)
    except CredentialsError as ex:
        raise ex from None

def add_otp_entry(kp, entry_title, issuer, entry_username, username, secret):
    if entry_title:
        title = entry_title
    elif issuer:
        title = issuer.replace(' ', '')
    else:
        title = username.replace(' ', '')
    if entry_username:
        username = entry_username
    elif not username:
        username = ''
    if len(kp.find_entries_by_title(title)) > 0:
        return f"Entry with title {title} already exists. Specify other title"
    kp.add_entry(kp.root_group, title, username, secret)
    kp.save()
    return f"Added {title}"

def escape_markdown_v2(text: str):
    return text.replace('\\', '\\\\').replace('*', '\\*').replace('_', '\\_').replace('[', '\\[').replace('`', '\\`')\
        .replace('.', '\\.').replace('-', '\\-').replace('!', '\\!').replace('#', '\\#').replace('(', '\\(')\
        .replace(')', '\\)').replace('+', '\\+').replace('=', '\\=').replace('~', '\\~').replace('|', '\\|')\
        .replace('>', '\\>').replace(']', '\\]').replace('{', '\\{').replace('}', '\\}')

def activate(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 1:
        (code,) = context.args
    else:
        return
    if str_hash(code) == config['activation_code_hash']:
        add_message_to_delete(message, user)
        set_user_data(user, rand_password(32), list())
        add_message_to_delete(message.reply_text("Activated"), user)

def create(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    users = users_db.getByQuery({"user": user})
    if len(users) != 1:
        return
    if len(context.args) == 2:
        master_password, fake_master_password = context.args
        trusted_user_ids = []
    elif len(context.args) == 3:
        master_password, fake_master_password, trusted_user_id = context.args
        trusted_user_ids = trusted_user_id.split(',')
    else:
        return
    if os.path.exists(user + '.kdbx'):
        try:
            kp = get_db(user, master_password)
            if kp:
                add_message_to_delete(message, user)
                add_message_to_delete(message.reply_text("Use /drop command before create"), user)
        except Exception as ex:
            log.exception("exception")
        return
    try:
        add_message_to_delete(message, user)
        create_db(user, master_password, fake_master_password, trusted_user_ids)
        add_message_to_delete(message.reply_text("Created"), user)
    except Exception as ex:
        log.exception("exception")

def list_entries(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 1:
        (master_password,) = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        if len(kp.root_group.entries) > 0:
            text = ', '.join([e.title for e in kp.root_group.entries])
            text = escape_markdown_v2(text)
        else:
            text = '_empty_'
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2), user)
    except Exception as ex:
        log.exception("exception")

def add(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 3:
        master_password, entry_title, password = context.args
        entry_username = ''
    elif len(context.args) == 4:
        master_password, entry_title, entry_username, password = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        if '"' in entry_title:
            text = f"Entry with title {entry_title} has invalid char: \""
        elif len(kp.find_entries_by_title(entry_title)) > 0:
            text = f"Entry with title {entry_title} already exists. Specify other title"
        else:
            kp.add_entry(kp.root_group, entry_title, entry_username, password)
            kp.save()
            text = "Added"
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def add_totp_by_qr(update: Update, _: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    args = message.caption.strip().replace("  ", " ").split(' ')
    if len(args) == 1:
        (master_password,) = args
        entry_title = ''
        entry_username = ''
    elif len(args) == 2:
        master_password, entry_title = args
        entry_username = None
    elif len(args) == 3:
        master_password, entry_title, entry_username = args
    else:
        return
    try:
        kp = get_db(user, master_password)
        if len(kp.find_entries_by_title(entry_title)) > 0:
            text = f"Entry with title {entry_title} already exists. Specify other title"
            add_message_to_delete(message, user)
            add_message_to_delete(message.reply_text(text), user)
            return
        try:
            f = max(message.photo, key=operator.attrgetter('file_size')).get_file()
            bytes = f.download_as_bytearray()
            decoded = decode_qr(bytes)
            issuer, username, secret = parse_totp(decoded[0].data)
        except:
            add_message_to_delete(message, user)
            add_message_to_delete(message.reply_text("Can't parse qr code"), user)
            return
        text = add_otp_entry(kp, entry_title, issuer, entry_username, username, secret)
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def add_otp(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 2:
        master_password, uri = context.args
        entry_title = ''
        entry_username = ''
    elif len(context.args) == 3:
        master_password, uri, entry_title = context.args
        entry_username = None
    elif len(context.args) == 4:
        master_password, uri, entry_title, entry_username = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        if len(kp.find_entries_by_title(entry_title)) > 0:
            text = f"Entry with title {entry_title} already exists. Specify other title"
            add_message_to_delete(message, user)
            add_message_to_delete(message.reply_text(text), user)
            return
        try:
            issuer, username, secret = parse_totp(uri)
        except:
            add_message_to_delete(message, user)
            add_message_to_delete(message.reply_text("Can't parse uri"), user)
            return
        text = add_otp_entry(kp, entry_title, issuer, entry_username, username, secret)
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def get(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 2:
        master_password, entry_title = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        entries = kp.find_entries_by_title(entry_title)
        if len(entries) != 1:
            text = "Not found"
        elif entries[0].username:
            text = f'Username: {entries[0].username}\nPassword: {entries[0].password}'
        else:
            text = entries[0].password
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def totp(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 2:
        master_password, entry_title = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        entries = kp.find_entries_by_title(entry_title)
        if len(entries) != 1:
            text = "Not found"
        else:
            text = pyotp.TOTP(entries[0].password).now()
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def set(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 3:
        master_password, entry_title, password = context.args
        entry_username = ''
    elif len(context.args) == 4:
        master_password, entry_title, entry_username, password = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        entries = kp.find_entries_by_title(entry_title)
        if len(entries) != 1:
            text = "Not found"
        else:
            entries[0].username = entry_username
            entries[0].password = password
            kp.save()
            text = "Updated"
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def delete(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 2:
        master_password, entry_title = context.args
    else:
        return
    try:
        kp = get_db(user, master_password)
        entries = kp.find_entries_by_title(entry_title)
        if len(entries) != 1:
            text = "Not found"
        else:
            kp.delete_entry(entries[0])
            kp.save()
            text = "Deleted"
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def export_db(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 1:
        (master_password,) = context.args
    else:
        return
    try:
        if get_db(user, master_password):
            filename = user + '.kdbx'
            with open(filename, 'rb') as f:
                add_message_to_delete(message, user)
                add_message_to_delete(message.reply_document(f.read(), filename), user)
    except Exception as ex:
        log.exception("exception")

def import_db(update: Update, _: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    users = users_db.getByQuery({"user": user})
    if len(users) != 1:
        return
    if not message.caption:
        return
    args = message.caption.strip().replace("  ", " ").split(' ')
    if len(args) == 2:
        master_password, fake_master_password = args
        trusted_user_ids = []
    elif len(args) == 3:
        master_password, fake_master_password, trusted_user_id = args
        trusted_user_ids = trusted_user_id.split(',')
    else:
        return
    if os.path.exists(user + '.kdbx'):
        try:
            kp = get_db(user, master_password)
            if kp:
                add_message_to_delete(message, user)
                add_message_to_delete(message.reply_text("Use /drop command before import"), user)
        except Exception as ex:
            log.exception("exception")
        return
    try:
        if not message.document or not message.document.file_name.endswith('.kdbx'):
            text = "Send .kdbx database"
        else:
            f = message.document.get_file()
            f.download(user + '.kdbx')
            try:
                kp = get_db(user, master_password)
            except:
                kp = None
            if kp:
                text = "Imported"
                set_user_data(user, fake_master_password, trusted_user_ids)
            else:
                remove(user + '.kdbx')
                text = "Import failed"
        add_message_to_delete(message, user)
        add_message_to_delete(message.reply_text(text), user)
    except Exception as ex:
        log.exception("exception")

def drop(update: Update, context: CallbackContext):
    message = update.message
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)
    if len(context.args) == 1:
        (master_password,) = context.args
    else:
        return
    if os.path.exists(user + '.kdbx'):
        try:
            kp = get_db(user, master_password)
            if kp:
                remove(user + '.kdbx')
                add_message_to_delete(message, user)
                add_message_to_delete(message.reply_text("Dropped"), user)
        except Exception as ex:
            log.exception("exception")

def trusted(update: Update, context: CallbackContext):
    message = update.message
    trusted_user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, trusted_user)
    if len(context.args) == 1:
        (fake_master_password,) = context.args
    else:
        return
    users = users_db.getByQuery({"fake_master_password": str_hash(fake_master_password)})
    users = list(filter(lambda u: trusted_user in u['trusted_user'], users))
    if len(users) == 1 and os.path.exists(users[0]['user'] + '.kdbx'):
        try:
            get_db(users[0]['user'], fake_master_password)
            add_message_to_delete(message, trusted_user)
            add_message_to_delete(message.reply_text("Dropped"), trusted_user)
        except Exception as ex:
            log.exception("exception")

def all_handler(update: Update, _: CallbackContext):
    message = update.message
    if not message:
        return
    user = user_id_hash(message.chat_id)
    add_incorrect_message_to_delete(message, user)


with open('config.json') as json_file:
    config = json.load(json_file)

users_db = db.getDb("users.json")

delete_message_queue_lock = threading.RLock()
incorrect_delete_message_queue = {}
delete_message_queue = list()
check_message_deleting_thread = threading.Thread(target=check_message_deleting)
check_message_deleting_thread.start()

updater = Updater(config['token'])
dispatcher = updater.dispatcher
bot = Bot(config['token'])

logging.basicConfig(filename='keepass.log', level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

dispatcher.add_handler(CommandHandler("activate", activate))
dispatcher.add_handler(CommandHandler("create", create))
dispatcher.add_handler(CommandHandler("list", list_entries))
dispatcher.add_handler(CommandHandler("add", add))
dispatcher.add_handler(MessageHandler(Filters.photo, add_totp_by_qr))
dispatcher.add_handler(CommandHandler("add_otp", add_otp))
dispatcher.add_handler(CommandHandler("get", get))
dispatcher.add_handler(CommandHandler("totp", totp))
dispatcher.add_handler(CommandHandler("set", set))
dispatcher.add_handler(CommandHandler("delete", delete))
dispatcher.add_handler(CommandHandler("export", export_db))
dispatcher.add_handler(MessageHandler(Filters.document, import_db))
dispatcher.add_handler(CommandHandler("drop", drop))
dispatcher.add_handler(CommandHandler("trusted", trusted))
dispatcher.add_handler(MessageHandler(Filters.all, all_handler))
updater.start_polling()
updater.idle()
