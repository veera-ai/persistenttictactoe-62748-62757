from fastapi import FastAPI, HTTPException, Depends, status, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
import sqlite3
import os

# Core FASTAPI setup
app = FastAPI(
    title="Tic Tac Toe Backend",
    description=(
        "Persistent backend API for multiplayer tic tac toe "
        "(user mgmt, game logic, match history, REST API)"
    ),
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User registration and login operations"},
        {"name": "games", "description": "Tic tac toe game management and play"},
        {"name": "history", "description": "Match history and statistics"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants/configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "devsecretkey")  # For prod, set a strong env var!
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 60 * 60 * 24  # 1 day

DATABASE_PATH = os.environ.get(
    "T3T_DB_PATH",
    os.path.join(os.path.dirname(__file__), "t3t_db.sqlite3")
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Database initialization (sqlite for simplicity, thread-check disabled for FastAPI dev server)
def get_db():
    db = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    with db:
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                created_at TIMESTAMP
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS games (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_x INTEGER,
                player_o INTEGER,
                current_turn TEXT,
                board TEXT,
                status TEXT,
                winner INTEGER,
                created_at TIMESTAMP,
                ended_at TIMESTAMP,
                FOREIGN KEY(player_x) REFERENCES users(id),
                FOREIGN KEY(player_o) REFERENCES users(id)
            )
            '''
        )
        db.execute(
            '''
            CREATE TABLE IF NOT EXISTS moves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                game_id INTEGER,
                user_id INTEGER,
                row INTEGER,
                col INTEGER,
                created_at TIMESTAMP,
                FOREIGN KEY(game_id) REFERENCES games(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            '''
        )
    db.close()


init_db()


# Helper/auth utility functions

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(
    token: str = Depends(
        lambda authorization: authorization.headers.get(
            "authorization", ""
        ).replace("Bearer ", "")
    )
):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token.",
        )
    payload = decode_access_token(token)
    if payload is None or "user_id" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        )
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (payload["user_id"],))
    user = cur.fetchone()
    db.close()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )
    return dict(user)


# ---- Pydantic MODELS ----

class RegisterRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=2,
        max_length=30,
        description="Unique username"
    )
    password: str = Field(
        ...,
        min_length=4,
        max_length=128,
        description="Password"
    )


class AuthToken(BaseModel):
    access_token: str = Field(..., description="JWT for session auth")
    token_type: Literal["bearer"] = "bearer"


class UserProfile(BaseModel):
    user_id: int
    username: str
    created_at: datetime


class GameCreateRequest(BaseModel):
    mode: Literal["public", "private"] = Field(
        "public",
        description="Game visibility"
    )
    as_player: Literal["X", "O"] = Field(
        "X",
        description="Which marker to play as"
    )


class GameJoinRequest(BaseModel):
    game_id: int
    as_player: Optional[Literal["X", "O"]]


class MoveRequest(BaseModel):
    row: int = Field(..., ge=0, le=2)
    col: int = Field(..., ge=0, le=2)


class MoveResponse(BaseModel):
    success: bool
    board: List[List[Optional[str]]]
    next_turn: Optional[str]
    winner: Optional[int]
    status: str


class GameStatusEnum(str):
    IN_PROGRESS = "IN_PROGRESS"
    WAITING = "WAITING"
    FINISHED = "FINISHED"


class GameSummary(BaseModel):
    id: int
    player_x: Optional[str]
    player_o: Optional[str]
    current_turn: Optional[str]
    board: List[List[Optional[str]]]
    status: str
    winner: Optional[str]
    created_at: datetime
    ended_at: Optional[datetime]


class MatchHistoryItem(BaseModel):
    id: int
    opponent: str
    result: Literal["win", "loss", "draw"]
    played_at: datetime


# ---- HELPER: Board Logic ----

def parse_board(board_str: str) -> List[List[Optional[str]]]:
    # Board is stored as a 9-char string: "X OX O   "
    return [
        [
            c if c in "XO" else None
            for c in board_str[i * 3:(i + 1) * 3]
        ]
        for i in range(3)
    ]


def board_to_str(board: List[List[Optional[str]]]) -> str:
    return "".join(
        [c if c in ["X", "O"] else " " for row in board for c in row]
    )


def check_winner(board: List[List[Optional[str]]]) -> Optional[str]:
    # Returns "X" or "O" (marker), or None
    lines = []
    lines.extend(board)
    lines.extend([[board[i][j] for i in range(3)] for j in range(3)])
    lines.append([board[i][i] for i in range(3)])
    lines.append([board[i][2 - i] for i in range(3)])
    for line in lines:
        if line.count(line[0]) == 3 and line[0] in ["X", "O"]:
            return line[0]
    if all(cell in ["X", "O"] for row in board for cell in row):
        return "draw"
    return None


# ---- API ROUTES ----

# PUBLIC_INTERFACE
@app.post("/register", response_model=AuthToken, summary="Register user", tags=["auth"])
def register(request: RegisterRequest = Body(...)):
    """Register a new user. Returns JWT token."""
    db = get_db()
    cur = db.execute(
        "SELECT id FROM users WHERE username = ?", (request.username,)
    )
    if cur.fetchone():
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists.")
    password_hash = get_password_hash(request.password)
    now = datetime.utcnow()
    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (request.username, password_hash, now)
    )
    db.commit()
    cur = db.execute(
        "SELECT id FROM users WHERE username = ?", (request.username,)
    )
    row = cur.fetchone()
    db.close()
    token = create_access_token({"user_id": row["id"]})
    return AuthToken(access_token=token, token_type="bearer")


# PUBLIC_INTERFACE
@app.post("/login", response_model=AuthToken, summary="User login", tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    """Login a user and get a JWT token."""
    db = get_db()
    cur = db.execute(
        "SELECT * FROM users WHERE username = ?", (form.username,)
    )
    user = cur.fetchone()
    db.close()
    if user is None or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    token = create_access_token({"user_id": user["id"]})
    return AuthToken(access_token=token, token_type="bearer")


# PUBLIC_INTERFACE
@app.post(
    "/games",
    response_model=GameSummary,
    summary="Create/Join a game",
    tags=["games"]
)
def create_join_game(
    request: GameCreateRequest = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """Creates a new game or automatically joins user to an existing open game."""
    db = get_db()
    if request.mode == "public":
        cur = db.execute(
            "SELECT * FROM games WHERE status = ? AND (player_x IS NULL OR player_o IS NULL)",
            (GameStatusEnum.WAITING,)
        )
        existing = cur.fetchone()
        if existing:
            if existing["player_x"] is None and request.as_player == "X":
                db.execute(
                    "UPDATE games SET player_x = ?, current_turn = ? WHERE id = ?",
                    (current_user["id"], "X", existing["id"])
                )
            elif existing["player_o"] is None and request.as_player == "O":
                db.execute(
                    "UPDATE games SET player_o = ? WHERE id = ?",
                    (current_user["id"], existing["id"])
                )
            else:
                db.close()
                raise HTTPException(
                    status_code=400,
                    detail="This slot already taken. Try as other marker."
                )
            db.commit()
            cur = db.execute(
                "SELECT * FROM games WHERE id = ?", (existing["id"],)
            )
            game = cur.fetchone()
            db.close()
            return _game_row_to_summary(game)
    board_str = " " * 9
    now = datetime.utcnow()
    player_x = current_user["id"] if request.as_player == "X" else None
    player_o = current_user["id"] if request.as_player == "O" else None
    status = GameStatusEnum.WAITING
    db.execute(
        "INSERT INTO games (player_x, player_o, current_turn, board, status, winner, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            player_x,
            player_o,
            "X",
            board_str,
            status,
            None,
            now
        )
    )
    game_id = db.execute(
        "SELECT last_insert_rowid() as id"
    ).fetchone()["id"]
    cur = db.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    new_game = cur.fetchone()
    db.commit()
    db.close()
    return _game_row_to_summary(new_game)


# PUBLIC_INTERFACE
@app.post(
    "/games/{game_id}/move",
    response_model=MoveResponse,
    summary="Make a move",
    tags=["games"]
)
def make_move(
    game_id: int = Path(..., description="ID of the game"),
    move: MoveRequest = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """Make a tic tac toe move. Returns move result and updated game board."""
    db = get_db()
    cur = db.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    game = cur.fetchone()
    if not game:
        db.close()
        raise HTTPException(status_code=404, detail="Game not found.")
    marker = None
    if current_user["id"] == game["player_x"]:
        marker = "X"
    elif current_user["id"] == game["player_o"]:
        marker = "O"
    else:
        db.close()
        raise HTTPException(
            status_code=403, detail="You are not part of this game."
        )
    if marker != game["current_turn"]:
        db.close()
        raise HTTPException(status_code=403, detail="Not your turn.")
    if (
        game["status"] != GameStatusEnum.IN_PROGRESS
        and game["status"] != GameStatusEnum.WAITING
    ):
        db.close()
        raise HTTPException(
            status_code=409, detail="Game already finished."
        )
    board = parse_board(game["board"])
    if board[move.row][move.col] is not None:
        db.close()
        raise HTTPException(
            status_code=400, detail="This cell is already occupied."
        )
    board[move.row][move.col] = marker
    winner = check_winner(board)
    next_turn = "O" if marker == "X" else "X"
    ended_at = None
    status = game["status"]
    winning_uid = None
    if winner == "X":
        status = GameStatusEnum.FINISHED
        winner_user_id = game["player_x"]
        winning_uid = winner_user_id
        ended_at = datetime.utcnow()
    elif winner == "O":
        status = GameStatusEnum.FINISHED
        winner_user_id = game["player_o"]
        winning_uid = winner_user_id
        ended_at = datetime.utcnow()
    elif winner == "draw":
        status = GameStatusEnum.FINISHED
        winning_uid = None
        ended_at = datetime.utcnow()
        next_turn = None
    else:
        if game["player_x"] and game["player_o"]:
            status = GameStatusEnum.IN_PROGRESS
        else:
            status = GameStatusEnum.WAITING
    db.execute(
        "UPDATE games SET board = ?, current_turn = ?, status = ?, winner = ?, ended_at = ? "
        "WHERE id = ?",
        (
            board_to_str(board),
            next_turn,
            status,
            winning_uid,
            ended_at,
            game_id,
        )
    )
    db.execute(
        "INSERT INTO moves (game_id, user_id, row, col, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            game_id,
            current_user["id"],
            move.row,
            move.col,
            datetime.utcnow(),
        )
    )
    db.commit()
    db.close()
    return MoveResponse(
        success=True,
        board=board,
        next_turn=next_turn,
        winner=winning_uid,
        status=status
    )


# PUBLIC_INTERFACE
@app.get(
    "/games/{game_id}",
    response_model=GameSummary,
    summary="Game status/details",
    tags=["games"]
)
def get_game(
    game_id: int = Path(..., description="Game ID"),
    current_user: dict = Depends(get_current_user)
):
    """Get the current game board, players, state."""
    db = get_db()
    cur = db.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    game = cur.fetchone()
    db.close()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found.")
    return _game_row_to_summary(game)


@app.get(
    "/users/{user_id}/matches",
    response_model=List[MatchHistoryItem],
    summary="User match history",
    tags=["history"]
)
def get_match_history(
    user_id: int = Path(..., description="User ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get all finished games and the user's results (win/loss/draw)
    """
    db = get_db()
    cur = db.execute(
        """
        SELECT g.id, g.player_x, x.username as xname, g.player_o, o.username as oname,
               g.status, g.winner, g.ended_at
        FROM games g
        LEFT JOIN users x ON g.player_x = x.id
        LEFT JOIN users o ON g.player_o = o.id
        WHERE (g.player_x = ? OR g.player_o = ?) AND g.status = ?
        ORDER BY g.ended_at DESC
        """,
        (user_id, user_id, GameStatusEnum.FINISHED)
    )
    rows = cur.fetchall()
    db.close()
    result = []
    for row in rows:
        if row["player_x"] == user_id:
            opponent = row["oname"] if row["oname"] else "(waiting)"
            if row["winner"] is None:
                res = "draw"
            elif row["winner"] == user_id:
                res = "win"
            else:
                res = "loss"
        else:
            opponent = row["xname"] if row["xname"] else "(waiting)"
            if row["winner"] is None:
                res = "draw"
            elif row["winner"] == user_id:
                res = "win"
            else:
                res = "loss"
        result.append(
            {
                "id": row["id"],
                "opponent": opponent,
                "result": res,
                "played_at": row["ended_at"],
            }
        )
    return result


@app.get("/", tags=["misc"])
def health_check():
    """Simple health check."""
    return {"message": "Healthy"}


def _game_row_to_summary(row) -> GameSummary:
    return GameSummary(
        id=row["id"],
        player_x=_get_username(row["player_x"]),
        player_o=_get_username(row["player_o"]),
        current_turn=row["current_turn"],
        board=parse_board(row["board"]),
        status=row["status"],
        winner=_get_username(row["winner"]) if row["winner"] else None,
        created_at=row["created_at"],
        ended_at=row["ended_at"] if row["ended_at"] else None
    )


def _get_username(user_id) -> Optional[str]:
    if not user_id:
        return None
    db = get_db()
    cur = db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    db.close()
    return row["username"] if row else None

# ---- OPENAPI METADATA FOR WEBSOCKET (Stub for future real-time, not implemented) ----
# You may use /games/{id} polling for now; add websockets for real-time later as needed.
