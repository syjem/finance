import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    # get the user's balance
    rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = rows[0]["cash"]

    # Retrieve the user's stock holdings
    rows = db.execute("""
        SELECT symbol, name, SUM(shares) AS total_shares, price, SUM(shares * price) AS total_value
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0 """, user_id)

    # create an empty table here first
    table_rows = []

    # for loop here to iterate stocks
    for row in rows:
        # get the current price of the stock
        stock = lookup(row["symbol"])
        price = stock["price"]

        # calculate the total value of the holding
        total_value = price * row["total_shares"]

        # append a row to the table
        table_rows.append({
            "symbol": row["symbol"],
            "name": row["name"],
            "shares": row["total_shares"],
            "price": usd(price),
            "total_value": usd(total_value)
        })
    # calculate the user's grand total
    grand_total = cash + sum([float(row["total_value"].replace('$', '').replace(',', '')) for row in table_rows])
    formatted_total = "${:,.2f}".format(grand_total)

    return render_template("index.html", rows=table_rows, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # form inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Form validation
        if not symbol:
            return apology("Field must not be empty!", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Symbol doesn't exist.", 400)

        if not shares:
            return apology("Missing shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("Invalid shares", 400)

        if shares < 1:
            return apology("Please, enter a number that is not less than 1.", 400)

        # get user infos
        user_id = session["user_id"]
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]
        cash = user["cash"]

        # calculate
        price = stock["price"]  # check the current price
        total = price * shares

        # check if user has enough cash
        if total > cash:
            return apology("Not enough balance!", 403)

        # else then buy the the stock
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total, user_id)  # update the users balance

        # Insert transactions into database
        name = stock["name"]
        now = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions(user_id, symbol, name, shares, price, timestamp) VALUES(?, ?, ?, ?, ?, ?)",
            user_id, symbol, name, shares, price, now
        )

        # redirect user to homepage
        flash("Stock purchased!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Query the database for all transactions for the current user
    rows = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", session["user_id"])

    # Render the transactions as an HTML table
    return render_template("history.html", rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        if not stock:
            return apology("Symbol doesn't exist!", 400)
        else:
            return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=usd(stock["price"]))

    # get method
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        retype_password = request.form.get("confirmation")

        # check for blank fields
        if not (username and password and retype_password):
            return apology("Field must not be empty", 400)

        # check if password is equal to retype password
        if password != retype_password:
            return apology("Password didn't match!", 400)

        # query to check for username availability
        username_rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        # check if username is already taken
        if len(username_rows) > 0:
            return apology("Username is already taken!", 400)

        # encrypt password
        hashed_password = generate_password_hash(password)
        # finally, add the user to database
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hashed_password)

        # redirect user to homepage
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        user_id = session["user_id"]

        # form validation
        if not symbol:
            flash("Invalid symbol", "danger")
            return redirect("/sell")

        if not shares:
            flash("Invalid shares", "danger")
            return redirect("/sell")

        # Lookup stock information
        quote = lookup(symbol)

        if not quote:
            flash("Invalid symbol", "danger")
            return redirect("/sell")

         # get user's current shares for the symbol
        rows = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ?", user_id, symbol)
        total_shares = sum([row["shares"] for row in rows])

        # ensure user has enough shares to sell
        shares = int(request.form.get("shares"))
        if total_shares < shares:
            return apology("Not enough shares to sell", 400)

        # calculate sale price
        sale_price = shares * quote["price"]

        # update user's cash balance
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + sale_price, session["user_id"])

        name = db.execute("SELECT name FROM transactions WHERE symbol = ?", symbol)[0]["name"]
        now = datetime.datetime.now()
        # update transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, symbol, name, -shares, quote["price"], now)

        flash("Sold successfully!", "success")
        return redirect("/")

    else:

        # get user's symbols with positive shares
        user_id = session["user_id"]
        rows = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

        return render_template("sell.html", symbols=[row["symbol"] for row in rows])
