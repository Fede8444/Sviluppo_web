
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
import secrets
import hashlib
import password
import email_config
import mysql.connector
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


# CONNESSIONE DATABASE
def connetti_db():
    return mysql.connector.connect(
        host="10.10.0.10",
        user="vecchia.federico",
        password=password.password,
        database="fvecchia"
    )


token_validi = set()


# INVIO EMAIL TRAMITE GMAIL
def invia_email(destinatario, oggetto, messaggio):
    email = EmailMessage()
    email["Subject"] = oggetto
    email["From"] = email_config.email
    email["To"] = destinatario
    email.set_content(messaggio)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(
            email_config.email,
            email_config.password_email.replace(" ", "")
        )
        server.send_message(email)


# GENERAZIONE CODICE DI 6 CIFRE
def genera_codice():
    return str(secrets.randbelow(900000) + 100000)


# CONTROLLO ACCESSO ALLE PAGINE PROTETTE
def login_required(f):
    @wraps(f)
    def decoratore(*args, **kwargs):
        token = session.get("token")

        if not token or token not in token_validi:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decoratore


# PAGINA INIZIALE
@app.route("/")
def home():
    return redirect(url_for("login"))


# REGISTRAZIONE
@app.route("/registrati", methods=["GET", "POST"])
def registrati():
    errore = None

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password_inserita = request.form.get("password", "")

        if not username or not password_inserita:
            errore = "Compila tutti i campi!"

        else:
            password_hash = hashlib.sha256(
                password_inserita.encode()
            ).hexdigest()

            conn = connetti_db()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id_persona, verificato FROM persone WHERE username = %s",
                (username,)
            )

            persona = cursor.fetchone()

            if persona is not None and persona[1] == 1:
                errore = "Questa email è già registrata!"

            else:
                codice = genera_codice()
                scadenza = datetime.now() + timedelta(minutes=10)

                if persona is None:
                    cursor.execute(
                        """
                        INSERT INTO persone
                        (username, pass, verificato, codice_verifica, scadenza_codice)
                        VALUES (%s, %s, 0, %s, %s)
                        """,
                        (username, password_hash, codice, scadenza)
                    )

                else:
                    cursor.execute(
                        """
                        UPDATE persone
                        SET pass = %s,
                            codice_verifica = %s,
                            scadenza_codice = %s
                        WHERE username = %s
                        """,
                        (password_hash, codice, scadenza, username)
                    )

                conn.commit()

                session["email_da_verificare"] = username

                cursor.close()
                conn.close()

                try:
                    invia_email(
                        username,
                        "Conferma il tuo account",
                        "Ciao!\n\n"
                        "Grazie per esserti registrato.\n\n"
                        "Il tuo codice di verifica è: " + codice +
                        "\n\nIl codice scade dopo 10 minuti."
                    )

                    return redirect(url_for("verifica"))

                except Exception as e:
                    print("Errore invio email:", e)
                    errore = "Non è stato possibile inviare l'email. Puoi richiedere un nuovo codice."

                    return render_template(
                        "registrati.html",
                        errore=errore
                    )

            cursor.close()
            conn.close()

    return render_template("registrati.html", errore=errore)


# VERIFICA EMAIL DURANTE LA REGISTRAZIONE
@app.route("/verifica", methods=["GET", "POST"])
def verifica():
    errore = None

    if request.method == "POST":
        codice_inserito = request.form.get("codice", "").strip()
        username = session.get("email_da_verificare")

        if not username:
            errore = "Sessione di verifica non valida. Registrati nuovamente."

        else:
            conn = connetti_db()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT codice_verifica, scadenza_codice
                FROM persone
                WHERE username = %s AND verificato = 0
                """,
                (username,)
            )

            risultato = cursor.fetchone()

            if risultato is None or risultato[0] is None:
                errore = "Codice non disponibile. Richiedine uno nuovo."

            elif risultato[0] != codice_inserito:
                errore = "Codice non corretto!"

            elif risultato[1] is None or datetime.now() > risultato[1]:
                errore = "Il codice è scaduto. Richiedine uno nuovo."

            else:
                cursor.execute(
                    """
                    UPDATE persone
                    SET verificato = 1,
                        codice_verifica = NULL,
                        scadenza_codice = NULL
                    WHERE username = %s
                    """,
                    (username,)
                )

                conn.commit()

                cursor.close()
                conn.close()

                session.pop("email_da_verificare", None)

                flash("Email verificata! Ora puoi effettuare il login.")
                return redirect(url_for("login"))

            cursor.close()
            conn.close()

    return render_template("verifica.html", errore=errore)


# RINVIO CODICE REGISTRAZIONE
@app.route("/rinvia-codice", methods=["POST"])
def rinvia_codice():
    username = session.get("email_da_verificare")

    if not username:
        return redirect(url_for("registrati"))

    codice = genera_codice()
    scadenza = datetime.now() + timedelta(minutes=10)

    conn = connetti_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE persone
        SET codice_verifica = %s,
            scadenza_codice = %s
        WHERE username = %s AND verificato = 0
        """,
        (codice, scadenza, username)
    )

    conn.commit()
    aggiornato = cursor.rowcount

    cursor.close()
    conn.close()

    if aggiornato == 0:
        return render_template(
            "verifica.html",
            errore="Non è possibile inviare un nuovo codice."
        )

    try:
        invia_email(
            username,
            "Nuovo codice di verifica",
            "Il tuo nuovo codice è: " + codice +
            "\n\nIl codice scade dopo 10 minuti."
        )

        flash("Nuovo codice inviato!")
        return redirect(url_for("verifica"))

    except Exception as e:
        print("Errore invio email:", e)

        return render_template(
            "verifica.html",
            errore="Errore durante l'invio. Riprova."
        )


# LOGIN - PRIMO CONTROLLO EMAIL E PASSWORD
@app.route("/login", methods=["GET", "POST"])
def login():
    errore = None

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password_inserita = request.form.get("password", "")

        password_hash = hashlib.sha256(
            password_inserita.encode()
        ).hexdigest()

        conn = connetti_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id_persona, pass, verificato
            FROM persone
            WHERE username = %s
            """,
            (username,)
        )

        persona = cursor.fetchone()

        if persona is None:
            errore = "Email non registrata!"

        elif persona[1] != password_hash:
            errore = "Password non corretta!"

        elif persona[2] == 0:
            errore = "Devi prima verificare la tua email!"

        else:
            codice = genera_codice()
            scadenza = datetime.now() + timedelta(minutes=10)

            cursor.execute(
                """
                UPDATE persone
                SET codice_verifica = %s,
                    scadenza_codice = %s
                WHERE id_persona = %s
                """,
                (codice, scadenza, persona[0])
            )

            conn.commit()

            session["login_da_verificare"] = persona[0]

            cursor.close()
            conn.close()

            try:
                invia_email(
                    username,
                    "Codice di sicurezza per il login",
                    "Ciao!\n\n"
                    "È stato richiesto un accesso al tuo account.\n\n"
                    "Il tuo codice di sicurezza è: " + codice +
                    "\n\nIl codice scade dopo 10 minuti.\n\n"
                    "Se non sei stato tu, ignora questa email."
                )

                return redirect(url_for("verifica_login"))

            except Exception as e:
                print("Errore invio email:", e)

                session.pop("login_da_verificare", None)

                errore = "Non è stato possibile inviare il codice. Riprova."

        cursor.close()
        conn.close()

    return render_template("login.html", errore=errore)


# SECONDO CONTROLLO LOGIN - CODICE EMAIL
@app.route("/verifica-login", methods=["GET", "POST"])
def verifica_login():
    errore = None

    if request.method == "POST":
        codice_inserito = request.form.get("codice", "").strip()
        id_persona = session.get("login_da_verificare")

        if not id_persona:
            errore = "Sessione di login non valida. Effettua nuovamente l'accesso."

        else:
            conn = connetti_db()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT codice_verifica, scadenza_codice
                FROM persone
                WHERE id_persona = %s AND verificato = 1
                """,
                (id_persona,)
            )

            risultato = cursor.fetchone()

            if risultato is None or risultato[0] is None:
                errore = "Codice non disponibile. Effettua nuovamente il login."

            elif risultato[0] != codice_inserito:
                errore = "Codice non corretto!"

            elif risultato[1] is None or datetime.now() > risultato[1]:
                errore = "Codice scaduto. Effettua nuovamente il login."

            else:
                cursor.execute(
                    """
                    UPDATE persone
                    SET codice_verifica = NULL,
                        scadenza_codice = NULL
                    WHERE id_persona = %s
                    """,
                    (id_persona,)
                )

                conn.commit()

                token = secrets.token_urlsafe(32)
                token_validi.add(token)

                session.pop("login_da_verificare", None)
                session["token"] = token
                session["id_persona"] = id_persona

                cursor.close()
                conn.close()

                flash("Accesso effettuato correttamente!")
                return redirect(url_for("form"))

            cursor.close()
            conn.close()

    return render_template("verifica_login.html", errore=errore)


# FORM PROTETTO
@app.route("/form", methods=["GET"])
@login_required
def form():
    return render_template("form.html")


@app.route("/invia", methods=["POST"])
@login_required
def invia():
    nome = request.form.get("nome", "")
    messaggio = request.form.get("messaggio", "")

    risultato = f"Nome: {nome} | Messaggio: {messaggio}"

    return render_template("form.html", risultato=risultato)


# SERVER RECORDS
@app.route("/server-records", methods=["GET"])
def server_records():
    valore = request.args.get("id")

    if valore == "flag":
        return "ciaooo"

    return "Parametro non valido", 400


# API DATI
@app.route("/api/dati", methods=["POST"])
def dati():
    contenuto = request.get_json(silent=True)

    if contenuto is None:
        return jsonify({"errore": "Invia un JSON valido"}), 400

    return jsonify({
        "ricevuto": True,
        "dati": contenuto
    })


# LOGOUT
@app.route("/logout")
def logout():
    token = session.pop("token", None)

    if token:
        token_validi.discard(token)

    session.clear()

    return redirect(url_for("login"))


# PERSONE
@app.route("/persone")
@login_required
def persone():
    conn = connetti_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM persone")
    risultati = cursor.fetchall()

    for persona in risultati:
        print(persona)

    cursor.close()
    conn.close()

    return "Dati stampati nel terminale"


if __name__ == "__main__":
    app.run(debug=True)
