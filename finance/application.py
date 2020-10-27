import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # get current user
    user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session['user_id'])
    user_cash = float(user[0]['cash'])
    grand_total = user_cash

    # get the user's shares
    shares = db.execute("SELECT * FROM shares WHERE user_id = :user_id ORDER BY symbol ASC",
                        user_id=session['user_id'])


    for share in shares:
        stock = lookup(share['symbol'])
        share['current_price'] = float(stock['price'])
        share['total'] = float(stock['price']) * share['shares']
        grand_total += float(stock['price']) * share['shares']

    return render_template("index.html", shares=shares, user_cash=user_cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # POST request
    if request.method == "POST":

        # get info from form
        symbol = request.form.get("symbol").upper()
        no_shares = request.form.get("shares")

        # get the current user id and user
        user_id = session.get("user_id")
        user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)

        # check for empty form fields
        if not symbol:
            return apology("need a symbol")
        elif not no_shares:
            return apology("need no of shares")

        # check quantity is positive number
        if not str(no_shares).isdigit():
            return apology("enter a number")
        if int(no_shares) < 1:
            return apology("no of shares should be 1 or more")



        # get the share
        share = lookup(symbol)

        # check that a share was found
        if not share:
            return apology("invalid symbol")

        # calculate total cost to buy
        total_cost = float(share['price']) * float(no_shares)

        # check user has enough cash to buy
        funds = float(user[0]['cash'])
        if funds < total_cost:
            return apology("not enough funds")

        # check if user has bought this share before
        owned_stock = db.execute("SELECT * FROM shares WHERE user_id = :user_id AND symbol = :symbol",
                           user_id=user_id, symbol=symbol)

        # if stock already owned, add quantity to entry in db
        if len(owned_stock) == 1:
            new_quantity = int(owned_stock[0]['shares']) + int(no_shares)
            db.execute("UPDATE shares SET shares = :new_quantity WHERE user_id = :user_id AND symbol = :symbol",
                        new_quantity=new_quantity, user_id=user_id, symbol=symbol)
        # if stock not owned, create db entry
        else:
            db.execute("INSERT INTO shares (user_id, symbol, name, shares) VALUES (?,?,?,?)",
                        user_id, symbol, share['name'], no_shares)

        # update the user's cash balance
        new_balance = float(user[0]['cash']) - total_cost
        db.execute("UPDATE users SET cash = :new_balance WHERE id = :user_id",
                    new_balance=new_balance, user_id=user_id)

        # save the transaction in history
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES (?,?,?,?)",
                   user_id, symbol, no_shares, share['price'])

        return redirect("/")

    # GET request
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # get history
    history = db.execute("SELECT * FROM history WHERE user_id = :user_id ORDER BY date DESC", user_id=session['user_id'])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # POST request
    if request.method == "POST":

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("invalid symbol")

        return render_template("quoted.html", stock=stock)

    # GET request
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
     # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation =  request.form.get("confirmation")

        # Ensure no missing inputs
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not confirmation:
            return apology("must confirm password", 403)

        # Check username doesn't already exist
        check = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(check) > 0:
            return apology("username taken", 403)

        # Check passwords match
        if password != confirmation:
            return apology ("passwords must match")

        # Hash the password and save to database
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username,hash) VALUES (?, ?)", (username, hashed_password))

        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # POST request
    if request.method == "POST":

        # get info from form
        symbol = request.form.get("symbol")
        no_shares = request.form.get("shares")

        # get the current user id and user
        user_id = session.get("user_id")
        user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)

        # check for empty form fields
        if not symbol:
            return apology("need a symbol")
        elif not no_shares:
            return apology("need no of shares")

        # check quantity is positive number
        if int(no_shares) < 1:
            return apology("no of shares should be 1 or more")
        if not no_shares.isnumeric():
            return apology("enter a number")

        # get the share
        share = lookup(symbol)

        # check that a share was found
        if not share:
            return apology("invalid symbol")

        # check user has enough shares to sell
        db_share = db.execute("SELECT * FROM shares WHERE user_id = :user_id AND symbol = :symbol",
                            user_id=user_id, symbol=symbol)

        if len(db_share) != 1:
            return (apology("you don't own any of these shares"))
        if int(db_share[0]['shares']) < int(no_shares):
            return (apology("you don't own enough of these shares"))

        # calculate total cost to sell
        total_cost = float(share['price']) * float(no_shares)

        # remove share from shares table
        new_no_shares = db_share[0]['shares'] - int(no_shares)
        db.execute("UPDATE shares SET shares = :new_no_shares WHERE symbol = :symbol AND user_id = :user_id",
                    new_no_shares=new_no_shares, symbol=symbol, user_id=user_id)

        # update the user's cash balance
        new_balance = float(user[0]['cash']) + total_cost
        db.execute("UPDATE users SET cash = :new_balance WHERE id = :user_id",
                    new_balance=new_balance, user_id=user_id)

        # save the transaction in history
        new_no_shares = f"-{no_shares}"
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES (?,?,?,?)",
                   user_id, symbol, new_no_shares, share['price'])

        return redirect("/")

    # GET request
    else:
        # get the user's owned stock
        symbols = []
        owned_stock = db.execute("SELECT * FROM shares WHERE user_id = :user_id",
                                 user_id = session.get('user_id'))
        for s in owned_stock:
            symbols.append(s['symbol'])

        return render_template("sell.html", symbols=symbols)


@app.route("/add_funds", methods=["GET", "POST"])
@login_required
def add_funds():
    """Add cash funds"""

    # POST request
    if request.method == "POST":

        # get amount from form and check validity
        amount = request.form.get("amount")
        try:
            float(amount)
        except ValueError:
            return apology("please enter a valid amount")

        # check amount is more than 0
        float_amount = float(amount)
        if float_amount <= 0:
            return apology("please enter a positive number")

        # get the user and current balance
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session.get("user_id"))

        # get new balance
        user_balance = float(user[0]['cash'])
        new_balance = user_balance + float_amount

        # save new balance to user
        db.execute("UPDATE users SET cash = :new_balance WHERE id = :user_id",
                    new_balance=new_balance, user_id=session.get("user_id"))

        return render_template("add_funds_success.html", new_balance=new_balance)

    # GET request
    else:
        # get the user's current cash balance
        user = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session.get("user_id"))
        balance = user[0]['cash']

        return render_template("add_funds.html", balance=balance)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
