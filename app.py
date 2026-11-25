
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
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


def connetti_db():
    return mysql.connector.connect(
        host="10.10.0.10",
        user="vecchia.federico",
        password=password.password,
        database="fvecchia"
    )


token_validi = set()


@app.before_request
def controllo_accesso():

    endpoint = request.endpoint

    if endpoint in ["login", "registrati", "password_dimenticata", "static"]:
        return

    if endpoint == "verifica":
        if (
            session.get("email_da_verificare")
            or session.get("login_da_verificare")
            or session.get("password_da_reimpostare")
        ):
            return
        return redirect(url_for("login"))

    if endpoint == "reimposta_password":
        if session.get("id_persona_reimposta"):
            return
        return redirect(url_for("password_dimenticata"))

    if endpoint == "rinvia_codice":
        if session.get("email_da_verificare"):
            return
        return redirect(url_for("registrati"))

    token = session.get("token")

    if not token or token not in token_validi:
        return redirect(url_for("login"))


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


def genera_codice():
    return str(secrets.randbelow(900000) + 100000)


def valida_password(password_inserita):
    return (
        len(password_inserita) >= 8
        and any(carattere.isupper() for carattere in password_inserita)
        and any(carattere.islower() for carattere in password_inserita)
        and any(carattere.isdigit() for carattere in password_inserita)
        and any(not carattere.isalnum() for carattere in password_inserita)
    )


def login_required(f):

    @wraps(f)
    def decoratore(*args, **kwargs):

        token = session.get("token")

        if not token or token not in token_validi:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decoratore


def admin_required(f):

    @wraps(f)
    @login_required
    def decoratore(*args, **kwargs):

        conn = connetti_db()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT ruolo FROM persone WHERE id_persona = %s",
                (session["id_persona"],)
            )

            risultato = cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

        if risultato is None or risultato[0] != "gestore":
            return redirect(url_for("home"))

        return f(*args, **kwargs)

    return decoratore


@app.route("/")
@login_required
def home():

    conn = connetti_db()
    cursor = conn.cursor()

    ricerca = request.args.get("q", "").strip()

    try:

        if ricerca:

            cursor.execute("""
                SELECT id_prodotto, nome, descrizione, prezzo, quantita
                FROM prodotti
                WHERE nome LIKE %s OR descrizione LIKE %s
                ORDER BY id_prodotto DESC
            """, ("%" + ricerca + "%", "%" + ricerca + "%"))

        else:

            cursor.execute("""
                SELECT id_prodotto, nome, descrizione, prezzo, quantita
                FROM prodotti
                ORDER BY id_prodotto DESC
            """)

        prodotti = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("negozio.html", prodotti=prodotti)


@app.route("/registrati", methods=["GET", "POST"])
def registrati():

    errore = None

    if request.method == "POST":

        username = request.form.get("username", "").strip().lower()
        password_inserita = request.form.get("password", "")

        if not username or not password_inserita:

            errore = "Compila tutti i campi!"

        elif not valida_password(password_inserita):

            errore = (
                "La password deve contenere almeno 8 caratteri, "
                "una lettera maiuscola, una minuscola, un numero "
                "e un carattere speciale."
            )

        else:

            password_hash = hashlib.sha256(
                password_inserita.encode()
            ).hexdigest()

            conn = connetti_db()
            cursor = conn.cursor()

            try:

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

                        cursor.execute("""
                            INSERT INTO persone
                            (username, pass, verificato, codice_verifica, scadenza_codice)
                            VALUES (%s, %s, 0, %s, %s)
                        """, (
                            username,
                            password_hash,
                            codice,
                            scadenza
                        ))

                    else:

                        cursor.execute("""
                            UPDATE persone
                            SET pass = %s,
                                codice_verifica = %s,
                                scadenza_codice = %s
                            WHERE username = %s
                        """, (
                            password_hash,
                            codice,
                            scadenza,
                            username
                        ))

                    conn.commit()

                    token = session.pop("token", None)

                    if token:
                        token_validi.discard(token)

                    session.pop("id_persona", None)
                    session.pop("ruolo", None)
                    session.pop("login_da_verificare", None)
                    session.pop("email_da_verificare", None)
                    session.pop("password_da_reimpostare", None)
                    session.pop("id_persona_reimposta", None)

                    session["email_da_verificare"] = username

            finally:
                cursor.close()
                conn.close()

            if errore is None:

                try:

                    invia_email(
                        username,
                        "Conferma il tuo account",
                        "Il tuo codice di verifica è: " + codice +
                        "\n\nIl codice scade dopo 10 minuti."
                    )

                    return redirect(url_for("verifica"))

                except Exception as e:

                    print("Errore invio email:", e)

                    session.pop("email_da_verificare", None)

                    return render_template(
                        "registrati.html",
                        errore="Non è stato possibile inviare l'email."
                    )

    return render_template("registrati.html", errore=errore)


@app.route("/verifica", methods=["GET", "POST"])
def verifica():

    errore = None

    email = session.get("email_da_verificare")
    id_persona_login = session.get("login_da_verificare")
    id_persona_reset = session.get("password_da_reimpostare")

    if not email and not id_persona_login and not id_persona_reset:
        return redirect(url_for("login"))

    if request.method == "POST":

        codice_inserito = request.form.get("codice", "").strip()

        conn = connetti_db()
        cursor = conn.cursor()

        try:

            if email:

                cursor.execute("""
                    SELECT id_persona, codice_verifica, scadenza_codice, ruolo
                    FROM persone
                    WHERE username = %s AND verificato = 0
                """, (email,))

            elif id_persona_login:

                cursor.execute("""
                    SELECT id_persona, codice_verifica, scadenza_codice, ruolo
                    FROM persone
                    WHERE id_persona = %s AND verificato = 1
                """, (id_persona_login,))

            else:

                cursor.execute("""
                    SELECT id_persona, codice_verifica, scadenza_codice, ruolo
                    FROM persone
                    WHERE id_persona = %s AND verificato = 1
                """, (id_persona_reset,))

            risultato = cursor.fetchone()

            if risultato is None or risultato[1] is None:

                errore = "Codice non disponibile."

            elif risultato[1] != codice_inserito:

                errore = "Codice non corretto!"

            elif risultato[2] is None or datetime.now() > risultato[2]:

                errore = "Il codice è scaduto."

            else:

                if email:

                    cursor.execute("""
                        UPDATE persone
                        SET verificato = 1,
                            codice_verifica = NULL,
                            scadenza_codice = NULL
                        WHERE id_persona = %s
                    """, (risultato[0],))

                else:

                    cursor.execute("""
                        UPDATE persone
                        SET codice_verifica = NULL,
                            scadenza_codice = NULL
                        WHERE id_persona = %s
                    """, (risultato[0],))

                conn.commit()

                id_persona = risultato[0]
                ruolo = risultato[3]

        finally:
            cursor.close()
            conn.close()

        if errore is None:

            if id_persona_reset:
                session.pop("password_da_reimpostare", None)
                session["id_persona_reimposta"] = id_persona_reset
                return redirect(url_for("reimposta_password"))

            session.pop("email_da_verificare", None)
            session.pop("login_da_verificare", None)

            token = secrets.token_urlsafe(32)
            token_validi.add(token)

            session["token"] = token
            session["id_persona"] = id_persona
            session["ruolo"] = ruolo

            if email:
                flash("Registrazione completata! Benvenuto su ElectroShop.")
            else:
                flash("Accesso effettuato correttamente!")

            if ruolo == "gestore":
                return redirect(url_for("admin"))

            return redirect(url_for("dashboard"))

    return render_template("verifica.html", errore=errore)


@app.route("/password-dimenticata", methods=["GET", "POST"])
def password_dimenticata():

    errore = None

    if request.method == "POST":

        username = request.form.get("username", "").strip().lower()

        if not username:
            errore = "Inserisci la tua email."

        else:

            conn = connetti_db()
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT id_persona
                    FROM persone
                    WHERE username = %s AND verificato = 1
                """, (username,))

                persona = cursor.fetchone()

                if persona is None:
                    errore = "Non esiste un account verificato con questa email."

                else:
                    codice = genera_codice()
                    scadenza = datetime.now() + timedelta(minutes=10)

                    cursor.execute("""
                        UPDATE persone
                        SET codice_verifica = %s,
                            scadenza_codice = %s
                        WHERE id_persona = %s
                    """, (codice, scadenza, persona[0]))

                    conn.commit()

            finally:
                cursor.close()
                conn.close()

            if errore is None:
                session.pop("email_da_verificare", None)
                session.pop("login_da_verificare", None)
                session.pop("id_persona_reimposta", None)
                session["password_da_reimpostare"] = persona[0]

                try:
                    invia_email(
                        username,
                        "Reimpostazione password ElectroShop",
                        "Il tuo codice per reimpostare la password è: " + codice +
                        "\n\nIl codice scade dopo 10 minuti."
                    )
                    return redirect(url_for("verifica"))

                except Exception as e:
                    print("Errore invio email:", e)
                    session.pop("password_da_reimpostare", None)
                    errore = "Non è stato possibile inviare l'email. Riprova."

    return render_template("password_dimenticata.html", errore=errore)


@app.route("/reimposta-password", methods=["GET", "POST"])
def reimposta_password():

    errore = None
    id_persona = session.get("id_persona_reimposta")

    if not id_persona:
        return redirect(url_for("password_dimenticata"))

    if request.method == "POST":

        nuova_password = request.form.get("password", "")
        conferma_password = request.form.get("conferma_password", "")

        if not valida_password(nuova_password):
            errore = (
                "La password deve contenere almeno 8 caratteri, "
                "una lettera maiuscola, una minuscola, un numero "
                "e un carattere speciale."
            )

        elif nuova_password != conferma_password:
            errore = "Le password non coincidono."

        else:
            password_hash = hashlib.sha256(
                nuova_password.encode()
            ).hexdigest()

            conn = connetti_db()
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    UPDATE persone
                    SET pass = %s
                    WHERE id_persona = %s AND verificato = 1
                """, (password_hash, id_persona))

                conn.commit()

            finally:
                cursor.close()
                conn.close()

            session.pop("id_persona_reimposta", None)
            flash("Password modificata correttamente. Ora puoi accedere.")
            return redirect(url_for("login"))

    return render_template("reimposta_password.html", errore=errore)


@app.route("/rinvia-codice", methods=["POST"])
def rinvia_codice():

    username = session.get("email_da_verificare")

    if not username:
        return redirect(url_for("registrati"))

    codice = genera_codice()
    scadenza = datetime.now() + timedelta(minutes=10)

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            UPDATE persone
            SET codice_verifica = %s,
                scadenza_codice = %s
            WHERE username = %s AND verificato = 0
        """, (codice, scadenza, username))

        conn.commit()
        aggiornato = cursor.rowcount

    finally:
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
            "Il tuo nuovo codice è: " + codice
        )

        flash("Nuovo codice inviato!")

        return redirect(url_for("verifica"))

    except Exception as e:

        print("Errore invio email:", e)

        return render_template(
            "verifica.html",
            errore="Errore durante l'invio. Riprova."
        )


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

        try:

            cursor.execute("""
                SELECT id_persona, pass, verificato
                FROM persone
                WHERE username = %s
            """, (username,))

            persona = cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

        if persona is None:

            errore = "Email non registrata!"

        elif persona[1] != password_hash:

            errore = "Password non corretta!"

        elif persona[2] == 0:

            errore = "Devi prima verificare la tua email!"

        else:

            codice = genera_codice()
            scadenza = datetime.now() + timedelta(minutes=10)

            conn = connetti_db()
            cursor = conn.cursor()

            try:

                cursor.execute("""
                    UPDATE persone
                    SET codice_verifica = %s,
                        scadenza_codice = %s
                    WHERE id_persona = %s
                """, (codice, scadenza, persona[0]))

                conn.commit()

            finally:
                cursor.close()
                conn.close()

            token = session.pop("token", None)

            if token:
                token_validi.discard(token)

            session.pop("id_persona", None)
            session.pop("ruolo", None)
            session.pop("email_da_verificare", None)
            session.pop("login_da_verificare", None)

            session["login_da_verificare"] = persona[0]

            try:

                invia_email(
                    username,
                    "Codice di sicurezza per il login",
                    "Il tuo codice di sicurezza è: " + codice +
                    "\n\nIl codice scade dopo 10 minuti."
                )

                return redirect(url_for("verifica"))

            except Exception as e:

                print("Errore invio email:", e)

                session.pop("login_da_verificare", None)

                errore = "Non è stato possibile inviare il codice."

    return render_template("login.html", errore=errore)


@app.route("/dashboard")
@login_required
def dashboard():

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT id_prodotto, nome, descrizione, prezzo, quantita
            FROM prodotti
            ORDER BY id_prodotto DESC
        """)

        prodotti = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("negozio.html", prodotti=prodotti)


@app.route("/prodotto/<int:id_prodotto>")
@login_required
def dettaglio_prodotto(id_prodotto):

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT id_prodotto, nome, descrizione, prezzo, quantita
            FROM prodotti
            WHERE id_prodotto = %s
        """, (id_prodotto,))

        prodotto = cursor.fetchone()

        if prodotto is None:
            return "Prodotto non trovato", 404

        cursor.execute("""
            SELECT AVG(voto), COUNT(*)
            FROM recensioni
            WHERE id_prodotto = %s
        """, (id_prodotto,))

        riepilogo = cursor.fetchone()

        media_voti = float(riepilogo[0]) if riepilogo[0] is not None else 0
        numero_recensioni = riepilogo[1]

        cursor.execute("""
            SELECT r.voto, r.commento, r.data_recensione, p.username
            FROM recensioni r
            JOIN persone p ON r.id_persona = p.id_persona
            WHERE r.id_prodotto = %s
            ORDER BY r.data_recensione DESC
        """, (id_prodotto,))

        recensioni = cursor.fetchall()

        cursor.execute("""
            SELECT id_recensione
            FROM recensioni
            WHERE id_prodotto = %s AND id_persona = %s
        """, (id_prodotto, session["id_persona"]))

        recensione_utente = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "prodotto.html",
        prodotto=prodotto,
        media_voti=media_voti,
        numero_recensioni=numero_recensioni,
        recensioni=recensioni,
        recensione_utente=recensione_utente
    )


@app.route("/prodotto/<int:id_prodotto>/recensione", methods=["POST"])
@login_required
def aggiungi_recensione(id_prodotto):

    voto = request.form.get("voto", "")
    commento = request.form.get("commento", "").strip()

    try:
        voto = int(voto)

        if voto < 1 or voto > 5:
            raise ValueError

    except ValueError:
        flash("Seleziona un voto valido da 1 a 5.")
        return redirect(url_for("dettaglio_prodotto", id_prodotto=id_prodotto))

    if not commento:
        flash("Inserisci un commento prima di pubblicare la recensione.")
        return redirect(url_for("dettaglio_prodotto", id_prodotto=id_prodotto))

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT id_prodotto
            FROM prodotti
            WHERE id_prodotto = %s
        """, (id_prodotto,))

        prodotto = cursor.fetchone()

        if prodotto is None:
            return "Prodotto non trovato", 404

        cursor.execute("""
            SELECT id_recensione
            FROM recensioni
            WHERE id_prodotto = %s AND id_persona = %s
        """, (id_prodotto, session["id_persona"]))

        recensione_esistente = cursor.fetchone()

        if recensione_esistente is not None:

            flash("Hai già pubblicato una recensione per questo prodotto.")

        else:

            cursor.execute("""
                INSERT INTO recensioni
                (id_prodotto, id_persona, voto, commento)
                VALUES (%s, %s, %s, %s)
            """, (
                id_prodotto,
                session["id_persona"],
                voto,
                commento
            ))

            conn.commit()

            flash("La tua recensione è stata pubblicata correttamente!")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("dettaglio_prodotto", id_prodotto=id_prodotto))


@app.route("/immagine/<int:id_prodotto>")
@login_required
def immagine_prodotto(id_prodotto):

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT immagine, tipo_immagine
            FROM prodotti
            WHERE id_prodotto = %s
        """, (id_prodotto,))

        risultato = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if risultato is None or risultato[0] is None:
        return "", 404

    return Response(
        risultato[0],
        mimetype=risultato[1] or "application/octet-stream"
    )


@app.route("/admin")
@admin_required
def admin():

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT id_prodotto, nome, descrizione, prezzo, quantita
            FROM prodotti
            ORDER BY id_prodotto DESC
        """)

        prodotti = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("admin.html", prodotti=prodotti)


@app.route("/admin/prodotto/nuovo", methods=["POST"])
@admin_required
def nuovo_prodotto():

    nome = request.form.get("nome", "").strip()
    descrizione = request.form.get("descrizione", "").strip()
    prezzo = request.form.get("prezzo", "")
    quantita = request.form.get("quantita", "")

    if not nome or not prezzo or not quantita:

        flash("Compila tutti i campi obbligatori.")

        return redirect(url_for("admin"))

    try:

        prezzo = float(prezzo)
        quantita = int(quantita)

        if prezzo < 0 or quantita < 0:
            raise ValueError

    except ValueError:

        flash("Prezzo o quantità non validi.")

        return redirect(url_for("admin"))

    file = request.files.get("immagine")

    immagine = None
    tipo_immagine = None

    if file and file.filename:

        if not file.mimetype.startswith("image/"):

            flash("Il file deve essere un'immagine.")

            return redirect(url_for("admin"))

        immagine = file.read()
        tipo_immagine = file.mimetype

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            INSERT INTO prodotti
            (nome, descrizione, prezzo, quantita, immagine, tipo_immagine)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            nome,
            descrizione,
            prezzo,
            quantita,
            immagine,
            tipo_immagine
        ))

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    flash("Prodotto aggiunto correttamente!")

    return redirect(url_for("admin"))


@app.route("/admin/prodotto/<int:id_prodotto>/modifica", methods=["GET", "POST"])
@admin_required
def modifica_prodotto(id_prodotto):

    conn = connetti_db()
    cursor = conn.cursor()

    if request.method == "POST":

        nome = request.form.get("nome", "").strip()
        descrizione = request.form.get("descrizione", "").strip()
        prezzo = request.form.get("prezzo", "")
        quantita = request.form.get("quantita", "")

        if not nome or not prezzo or not quantita:

            flash("Compila tutti i campi obbligatori.")

            cursor.close()
            conn.close()

            return redirect(url_for("admin"))

        try:

            prezzo = float(prezzo)
            quantita = int(quantita)

            if prezzo < 0 or quantita < 0:
                raise ValueError

        except ValueError:

            flash("Prezzo o quantità non validi.")

            cursor.close()
            conn.close()

            return redirect(url_for("admin"))

        file = request.files.get("immagine")

        if file and file.filename:

            if not file.mimetype.startswith("image/"):

                flash("Il file deve essere un'immagine.")

                cursor.close()
                conn.close()

                return redirect(url_for("admin"))

            cursor.execute("""
                UPDATE prodotti
                SET nome = %s,
                    descrizione = %s,
                    prezzo = %s,
                    quantita = %s,
                    immagine = %s,
                    tipo_immagine = %s
                WHERE id_prodotto = %s
            """, (
                nome,
                descrizione,
                prezzo,
                quantita,
                file.read(),
                file.mimetype,
                id_prodotto
            ))

        else:

            cursor.execute("""
                UPDATE prodotti
                SET nome = %s,
                    descrizione = %s,
                    prezzo = %s,
                    quantita = %s
                WHERE id_prodotto = %s
            """, (
                nome,
                descrizione,
                prezzo,
                quantita,
                id_prodotto
            ))

        conn.commit()

        cursor.close()
        conn.close()

        flash("Prodotto modificato correttamente!")

        return redirect(url_for("admin"))

    try:

        cursor.execute("""
            SELECT id_prodotto, nome, descrizione, prezzo, quantita
            FROM prodotti
            WHERE id_prodotto = %s
        """, (id_prodotto,))

        prodotto = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if prodotto is None:
        return "Prodotto non trovato", 404

    return render_template("modifica_prodotto.html", prodotto=prodotto)


@app.route("/admin/prodotto/<int:id_prodotto>/elimina", methods=["POST"])
@admin_required
def elimina_prodotto(id_prodotto):

    conn = connetti_db()
    cursor = conn.cursor()

    try:

        cursor.execute(
            "DELETE FROM prodotti WHERE id_prodotto = %s",
            (id_prodotto,)
        )

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    flash("Prodotto eliminato.")

    return redirect(url_for("admin"))


@app.route("/form")
@login_required
def form():

    return redirect(url_for("dashboard"))


@app.route("/invia", methods=["POST"])
@login_required
def invia():

    nome = request.form.get("nome", "")
    messaggio = request.form.get("messaggio", "")

    risultato = f"Nome: {nome} | Messaggio: {messaggio}"

    return render_template("form.html", risultato=risultato)


@app.route("/server-records")
@login_required
def server_records():

    valore = request.args.get("id")

    if valore == "flag":
        return "ciaooo"

    return "Parametro non valido", 400


@app.route('/chi-siamo')
def chi_siamo():
    return render_template('chi_siamo.html')


@app.route("/api/dati", methods=["POST"])
@login_required
def dati():

    contenuto = request.get_json(silent=True)

    if contenuto is None:
        return jsonify({"errore": "Invia un JSON valido"}), 400

    return jsonify({
        "ricevuto": True,
        "dati": contenuto
    })


@app.route("/logout")
@login_required
def logout():

    token = session.pop("token", None)

    if token:
        token_validi.discard(token)

    session.clear()

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
