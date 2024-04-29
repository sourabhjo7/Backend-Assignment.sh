from dotenv import load_dotenv
import hashlib
import os
import re
import tempfile
from urllib.parse import urlparse
from fastapi import Depends, FastAPI, Header, Request, Security
from fastapi.security import APIKeyHeader, HTTPBearer, OAuth2PasswordBearer
import requests
import uvicorn
from fastapi.responses import JSONResponse
from fastapi import HTTPException, status
from models import Repo, SignUpSchema,LoginSchema,AuthHeader,Token
from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import shutil
import pyrebase # type: ignore
from pymongo import MongoClient
load_dotenv() 

# Connect to MongoDB
client = MongoClient(os.getenv('MONGODB_URI'))
db = client['code_db']
collection = db['code_data']
app = FastAPI(
    description="this is a backend System manage metadata about functions in a codebase and provide an API for retrieving specific function code based on an identifier",
    title="Function Codebase API Backend System (Assignment momentum.sh)",
    version="1.0.0",
    docs_url="/",
    )
# 

import firebase_admin #type: ignore
from firebase_admin import credentials,auth # type: ignore


if not firebase_admin._apps:
    cred = credentials.Certificate(os.getenv('FIREBASE_SERVICE_ACCOUNT_KEY')) #get your service account keys from firebase
    firebase_admin.initialize_app(cred)


firebaseConfig = {
  "apiKey": os.getenv('FIREBASE_API_KEY'),
  "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
  "projectId": os.getenv('FIREBASE_PROJECT_ID'),
  "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET'),
  "messagingSenderId": os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
  "appId": os.getenv('FIREBASE_APP_ID'),
  "measurementId": os.getenv('FIREBASE_MEASUREMENT_ID'),
  "databaseURL":""
}

firebase = pyrebase.initialize_app(firebaseConfig)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected server error occurred."},
    )

api_key_header = APIKeyHeader(name="Authorization", auto_error=True)


async def get_auth_header(request:Request):
    authorization = request.headers.get("Authorization")
    print(authorization)
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header is missing"
        )
    return AuthHeader(authorization=authorization)



async def validate_token(auth_header: AuthHeader = Depends(get_auth_header)):
    if "Bearer " in auth_header.authorization:
        token = auth_header.authorization.split("Bearer ")[1]
    else:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header"
        )
    print(token)
    try:
        # Verify the ID token while checking if the token is revoked by
        # passing check_revoked=True.
        decoded_token = auth.verify_id_token(token, check_revoked=True)
        # Token is valid and the user is allowed to access protected routes.
        return decoded_token
    except ValueError:
        # This error will be raised if the token is expired or any other error
        # occurred while decoding the token.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except auth.RevokedIdTokenError:
        # Token has been revoked. Inform the user to reauthenticate or sign out.
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,#type: ignore
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/healthcheck")
async def root():
    return {"message": "hello world"}




@app.post('/signup')
async def create_an_account(user_data: SignUpSchema):
    email = user_data.email
    password = user_data.password
    print("sign up co routine")
    try:
        user = auth.create_user(
            email = email,
            password = password
        )
        return JSONResponse(content={"message" : f"User account created successfuly for user {user.uid}"},
                            status_code= 201
               )
    except auth.EmailAlreadyExistsError:
        raise HTTPException(
            status_code=400,
            detail= f"Account already created for the email {email}"
        )


@app.post('/login')
async def create_access_token(user_data:LoginSchema):
    email = user_data.email
    password = user_data.password

    try:
        user = firebase.auth().sign_in_with_email_and_password(
            email = email,
            password = password
        )

        token = user['idToken']

        return JSONResponse(
            content={
                "token":token
            },status_code=200
        )

    except:
        raise HTTPException(
            status_code=400,detail="Invalid Credentials"
        )

@app.get('/authenticate')
async def authenticate(auth_header: AuthHeader = Depends(get_auth_header),user: str = Depends(validate_token),authorization: str =Header(None)):
    # print(user, auth_header)
    # , 
    
    return JSONResponse(
        content={
            "message":"User is authenticated",
            "user":user,
        },status_code=200
    )
from tree_sitter import Node 

def extract_info(node: Node, code: str):
    if node.type in ["function_definition", "class_definition", "decorated_definition"]:
        return {
            "type": node.type,
            "name": node.children[1].text,
            "code": code[node.start_byte:node.end_byte]
        }
   

@app.post("/repo")
async def get_repo_data(repo: Repo,user: str = Depends(validate_token),authorization: str =Header(None)):
    # Parse the URL to get the owner and repo
    parsed_url = urlparse(repo.url)
    userdata=dict(user)
    print(type(userdata),type(user))
    path_parts = parsed_url.path.strip("/").split("/")
    if len(path_parts) < 2:
        raise HTTPException(
            status_code=400, 
            detail="Invalid GitHub URL"
        )
    owner, repo = path_parts[:2]

    # Fetch repository data
    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(repo_url)
    if response.status_code != 200:
        raise HTTPException(
            status_code=400, 
            detail="Could not fetch data from GitHub"
        )
    repo_data = response.json()

    # Fetch repository code
    code_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
    response = requests.get(code_url)
    if response.status_code != 200:
        raise HTTPException(
            status_code=400, 
            detail="Invalid GitHub URL or could not fetch data"
        )
    code_data = response.json()

    # Create a temporary directory to store the code
    temp_dir = tempfile.mkdtemp()

    try:
        # Download and extract the code to the temporary directory
        download_url = repo_data["archive_url"].replace("{archive_format}{/ref}", "zipball/main")
        
        response = requests.get(download_url, stream=True)

        if response.status_code != 200 or response.headers.get('Content-Type') != 'application/zip':
            raise HTTPException(
                status_code=400, 
                detail="Could not fetch code from GitHub or the fetched file is not a zip file"
             )

        # Get the file name from the Content-Disposition header
        content_disposition = response.headers.get('Content-Disposition')
        filename = re.findall('filename=(.+)', content_disposition)[0] if content_disposition else 'code.zip'

        with open(os.path.join(temp_dir, filename), "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        shutil.unpack_archive(os.path.join(temp_dir, filename), temp_dir)

        # Parse the code with Tree-sitter
        # Note: You need to build the Tree-sitter language library for your language and point to it here
       
        # Language.build_library(
        #   'build/my-languages.so',
        #   ['tree-sitter-python']
        # )
        # PY_LANGUAGE = Language('build/my-languages.so', 'python')
        
        #PY_LANGUAGE = Language(tspython.language(), "python")
        parser = Parser()
        #parser.set_language(PY_LANGUAGE)

        function_info = []
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                    if file.endswith(".py"):
                        LANGUAGE = Language(tspython.language(), "python")
                    elif file.endswith(".js"):
                        LANGUAGE = Language(tsjavascript.language(), "javascript")
                    else:
                        continue  # Skip files of other languages
                
                    parser.set_language(LANGUAGE)
                    with open(os.path.join(root, file), "r") as f:
                        code = f.read()
                             
                    tree = parser.parse(bytes(code, "utf8"))
                    print("treee==>",tree.root_node.children)
                    # Traverse the syntax tree and extract function information
                    # This is a simplified example and may not work for all cases
                    for node in tree.root_node.children:
                        info = extract_info(node, code)
                        if info is not None:
                            unique_hash = hashlib.sha256(f"{file}_{info['name']}".encode()).hexdigest()
                            info["Identifier"] = f"{info['type']}_{unique_hash}"
                            function_info.append(info)
                            
                    
        
        existing_user = collection.find_one({"userId": userdata["sub"]})
        if existing_user:
            existing_meta_data = existing_user.get("meta_data", [])
            existing_meta_data.extend(function_info)
            collection.update_one({"userId": userdata["sub"]}, {"$set": {"meta_data": existing_meta_data}})
        else:
            collection.insert_one({"userId": userdata["sub"], "meta_data": function_info})
            
        return {"meta_data": function_info}
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)
    
    
@app.get("/function/{identifier}")
async def get_function_code(identifier: str,user: str = Depends(validate_token),authorization: str =Header(None)):
    print("get function code")
    userdata=dict(user)
    print(userdata["sub"])
    # Get the function code from the database
    user = collection.find_one({"userId": userdata["sub"]})
    for function_code in user["meta_data"]:
        if function_code["Identifier"] == identifier:
            return {"code": function_code["code"]}
    
    raise HTTPException(
        status_code=404, 
        detail="Function code not found or user does not have access to the function"
    )



if __name__ == "__main__":
    uvicorn.run("main:app",reload=True)