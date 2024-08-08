import argparse
import hashlib
import os
import requests
from dotenv import load_dotenv
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.customaudience import CustomAudience
from facebook_business.api import FacebookAdsApi
from datetime import datetime, timedelta
import pymysql
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import base64


environment = os.environ.get('FLASK_ENV')
if environment == 'development':
    print("In Development Mode")
    from dotenv import load_dotenv
    load_dotenv()
else:
    print("In Production Mode")

# Environment variables
access_token = os.getenv('access_token')
app_secret = os.getenv('app_secret')
app_id = os.getenv('app_id')
ad_account_id = os.getenv('ad_account_id')
host=os.getenv('host')
database=os.getenv('database')
user=os.getenv('user')
password=os.getenv('password')
Facebook_custom_audience=os.getenv('Facebook_custom_audience')

encryption_key= os.getenv('ENCRYPTION_KEY')
# Add padding if necessary
missing_padding = 4 - len(encryption_key) % 4
if missing_padding != 4:
    encryption_key += '=' * missing_padding
key = base64.urlsafe_b64decode(encryption_key.encode())

def decrypt_data(encrypted_data, key):
    if not encrypted_data:  # Check if the encrypted_data is empty or None
        return ''  # Return an empty string if the input is empty

    try:
        # Ensure key length is appropriate for AES (16, 24, or 32 bytes)
        if len(key) not in {16, 24, 32}:
            raise ValueError("Key length must be 16, 24, or 32 bytes.")
        
        encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    
    except (ValueError, InvalidTag) as e:
        print(f"Decryption failed: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def batch(iterable, n):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]

def hash_email(email):
    email = email.strip().lower() 
    return hashlib.sha256(email.encode('utf-8')).hexdigest()

def fetch_emails_from_db():
    connection = pymysql.connect(
        host=host,
        user=user,
        password=password,
        db=database
    )
    try:
        with connection.cursor() as cursor:
            sql = "SELECT email FROM ffstuff.MemberpressUserListCurrent WHERE currentMembership NOT IN (0,714) AND status = 'active'"
            cursor.execute(sql)
            result = cursor.fetchall()
            emails = [decrypt_data(row[0],key) for row in result]
        return emails
    finally:
        connection.close()

def add_emails_to_custom_audience(custom_audience_id):
    FacebookAdsApi.init(access_token=access_token)
    custom_audience = CustomAudience(custom_audience_id)
    schema = CustomAudience.Schema.email_hash
    emails = fetch_emails_from_db()

    hashed_emails = [hash_email(email) for email in emails]
    batch_size = 1000 
    for email_batch in batch(hashed_emails, batch_size):
        response = custom_audience.add_users(schema=schema, users=email_batch)
        print(f"Added {len(email_batch)} email(s) to custom audience.")
        print(email_batch)
        print("Batch response:", response.json())  # Print the JSON-like dict


def daily_upload(request):
    add_emails_to_custom_audience(Facebook_custom_audience)

if __name__ == "__main__":
    # For local testing


    # Argument parser setup
    parser = argparse.ArgumentParser(description='Facebook Ads API script')
    parser.add_argument('--update-emails', action='store_true', help='update email addresses to the custom audience')

    args = parser.parse_args()

    if  args.update_emails:
        add_emails_to_custom_audience(120210377268320510)
    else:
        print("No action specified. Use --get-token or --create-audience.")
