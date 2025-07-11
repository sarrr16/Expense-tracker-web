from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import os
from bson import ObjectId
import asyncio

app = FastAPI(title="Expense Tracker API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-this-in-production")
ALGORITHM = "HS256"

# MongoDB setup
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGODB_URL)
db = client.expense_tracker

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ExpenseCreate(BaseModel):
    category: str
    upi_amount: float
    cash_amount: float
    description: Optional[str] = ""

class ExpenseResponse(BaseModel):
    id: str
    category: str
    upi_amount: float
    cash_amount: float
    total_amount: float
    description: str
    created_at: datetime

class UserStats(BaseModel):
    total_expenses: float
    category_breakdown: dict
    monthly_summary: dict

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# Serve the HTML file
@app.get("/", response_class=HTMLResponse)
async def get_index():
    try:
        with open("index.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Index.html not found</h1>", status_code=404)

# API Routes
@app.post("/register")
async def register(user: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"$or": [{"username": user.username}, {"email": user.email}]})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user
    hashed_password = hash_password(user.password)
    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_doc)
    
    # Create access token
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer", "message": "User registered successfully"}

@app.post("/login")
async def login(user: UserLogin):
    db_user = await db.users.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/expenses", response_model=ExpenseResponse)
async def create_expense(expense: ExpenseCreate, current_user: dict = Depends(get_current_user)):
    expense_doc = {
        "user_id": current_user["_id"],
        "category": expense.category,
        "upi_amount": expense.upi_amount,
        "cash_amount": expense.cash_amount,
        "total_amount": expense.upi_amount + expense.cash_amount,
        "description": expense.description,
        "created_at": datetime.utcnow()
    }
    
    result = await db.expenses.insert_one(expense_doc)
    expense_doc["id"] = str(result.inserted_id)
    
    return ExpenseResponse(**expense_doc)

@app.get("/expenses", response_model=List[ExpenseResponse])
async def get_expenses(current_user: dict = Depends(get_current_user)):
    expenses_cursor = db.expenses.find({"user_id": current_user["_id"]}).sort("created_at", -1)
    expenses = await expenses_cursor.to_list(length=None)
    
    return [
        ExpenseResponse(
            id=str(expense["_id"]),
            category=expense["category"],
            upi_amount=expense["upi_amount"],
            cash_amount=expense["cash_amount"],
            total_amount=expense["total_amount"],
            description=expense["description"],
            created_at=expense["created_at"]
        )
        for expense in expenses
    ]

@app.get("/expenses/stats", response_model=UserStats)
async def get_user_stats(current_user: dict = Depends(get_current_user)):
    # Get all expenses for user
    expenses_cursor = db.expenses.find({"user_id": current_user["_id"]})
    expenses = await expenses_cursor.to_list(length=None)
    
    # Calculate total expenses
    total_expenses = sum(expense["total_amount"] for expense in expenses)
    
    # Category breakdown
    category_breakdown = {}
    for expense in expenses:
        category = expense["category"]
        if category not in category_breakdown:
            category_breakdown[category] = 0
        category_breakdown[category] += expense["total_amount"]
    
    # Monthly summary (last 6 months)
    monthly_summary = {}
    for expense in expenses:
        month_key = expense["created_at"].strftime("%Y-%m")
        if month_key not in monthly_summary:
            monthly_summary[month_key] = 0
        monthly_summary[month_key] += expense["total_amount"]
    
    return UserStats(
        total_expenses=total_expenses,
        category_breakdown=category_breakdown,
        monthly_summary=monthly_summary
    )

@app.delete("/expenses/{expense_id}")
async def delete_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    try:
        result = await db.expenses.delete_one({"_id": ObjectId(expense_id), "user_id": current_user["_id"]})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found")
        return {"message": "Expense deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid expense ID")

@app.get("/health")
async def health_check():
    return {"message": "Expense Tracker API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
