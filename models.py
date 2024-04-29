from pydantic import BaseModel


class Repo(BaseModel):
    url: str
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://github.com/Dart9000/Inspect-API"
                }
            }

class SignUpSchema(BaseModel):
    email:str
    password:str

    class Config:
        json_schema_extra = {
            "example":{
                "email":"test@gmail.com",
                "password":"testpass123"
            }
        }


class LoginSchema(BaseModel):
    email:str
    password:str

    class Config:
        json_schema_extra ={
            "example":{
                "email":"test@gmail.com",
                "password":"testpass123"
            }
        }                

class Token(BaseModel):
    token: str

    class Config:
        json_schema_extra = {
            "example": {
                "token": "Bearer eyJhbGciOi...."
            }
        }


class AuthHeader(BaseModel):
    authorization: str

    class Config:
        json_schema_extra = {
            "example": {
                "authorization": "Bearer eyJhbGciOi...."
            }
        }