# Command handler originally created to send emails
# It is not used though, because mails are sent from the eid record server now

import cryptography.x509 as x509
import cryptography.x509.oid as oid
import src.controller.command_handler.signauthutils as utils
import src.controller.logger as logger
import sys
import smtplib
import ssl
from src.controller.commands import Command
from dotenv import load_dotenv
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def run(certificate, command, origin):
    try:
        load_dotenv()
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"

        #cert personal
        ruta = os.getenv("EID_RECORD_SERVER_MAIL_PATH")
        mail_file = open(ruta, "rt")
        sender_email = mail_file.readline()[:-1]
        pw = mail_file.readline()

        subject = certificate.subject.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)[0].value
        receiver_email = utils.get_mail_from_cert(certificate)
        if(receiver_email == None):
            return

        message = build_message(
            sender_email, receiver_email, command, subject, origin)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, pw)
            dict_response = server.sendmail(
                sender_email, receiver_email, message)
            if len(dict_response) > 0:
                logger.log_error(
                    "sendmail.run: failed to send mail to address " + receiver_email)
                sys.exit(0)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.log_error(str(exc_tb.tb_lineno) + " sendMail.run: " + str(e))
        sys.exit(0)


def build_message(sender_email, receiver_email, command, cert_subject, origin):
    if command == Command.AUTHENTICATE:
        command_type = "Authentication"
    elif command == Command.SIGN:
        command_type = "Signing"

    message = MIMEMultipart("alternative")
    message["Subject"] = "EID record server " + command_type + " alert"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    text = command_type + "attempt in web: " + origin + "\
        whit certificate from subject: """
    text += cert_subject

    html = """\
    <html>
    <body>
        <p>"""
    html += command_type
    html += " attempt with certificate from subject: """
    html += cert_subject
    html += """ <br> 
        in web: <a href=" """
    html += origin
    html += """ "> """
    html += origin
    html += """</a> 
        </p>
    </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)
    return message.as_string()
