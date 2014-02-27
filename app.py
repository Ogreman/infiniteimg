# check.py

import sys
import json
import argparse
import time, os, json, base64, hmac, urllib

from flask import Flask, render_template, request, redirect, Response, url_for
from hashlib import sha1
from unipath import Path

from boto.s3.connection import S3Connection
from boto.s3.bucket import Bucket

TEMPLATE_DIR = Path(__file__).ancestor(1).child("templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)


def get_keys():
    return (
        os.environ.get('AWS_ACCESS_KEY_ID'),
        os.environ.get('AWS_SECRET_ACCESS_KEY'),
        os.environ.get('S3_BUCKET_NAME')
    )


def get_bucket(key, secret, bucket_name):
    conn = S3Connection(key, secret)
    return Bucket(conn, bucket_name)


@app.route("/submit_form/", methods=["POST"])
def submit_form():
    key, secret, bucket_name = get_keys()
    bucket = get_bucket(key, secret, bucket_name)
    for k in bucket.list():
        if k.name != request.form["image_url"].split('/')[-1]:
            bucket.delete_key(k.key)
    return redirect(url_for('index'))


@app.route('/sign_s3/')
def sign_s3():
    # Load necessary information into the application:
    AWS_ACCESS_KEY, AWS_SECRET_KEY, S3_BUCKET = get_keys()

    # Collect information on the file from the GET parameters of the request:
    object_name = urllib.quote_plus(request.args.get('s3_object_name'))
    mime_type = request.args.get('s3_object_type')

    # Set the expiry time of the signature (in seconds) and declare the permissions of the file to be uploaded
    expires = int(time.time()+10)
    amz_headers = "x-amz-acl:public-read"

    # Generate the PUT request that JavaScript will use:
    put_request = "PUT\n\n%s\n%d\n%s\n/%s/%s" % (mime_type, expires, amz_headers, S3_BUCKET, object_name)

    # Generate the signature with which the request can be signed:
    signature = base64.encodestring(hmac.new(AWS_SECRET_KEY, put_request, sha1).digest())
    # Remove surrounding whitespace and quote special characters:
    signature = urllib.quote_plus(signature.strip())

    # Build the URL of the file in anticipation of its imminent upload:
    url = 'https://%s.s3.amazonaws.com/%s' % (S3_BUCKET, object_name)

    content = json.dumps({
        'signed_request': '%s?AWSAccessKeyId=%s&Expires=%d&Signature=%s' % (url, AWS_ACCESS_KEY, expires, signature),
        'url': url
    })

    # Return the signed request and the anticipated URL back to the browser in JSON format:
    return Response(content, mimetype='text/plain; charset=x-user-defined')


@app.route('/')
def index():
    """
    Return the main view.
    """
    def get_image():
        key, secret, bucket_name = get_keys()
        bucket = get_bucket(key, secret, bucket_name)
        keys = bucket.get_all_keys()
        keys.sort(key=lambda x: x.last_modified)
        return 'https://{bucket_name}.s3.amazonaws.com/{image}'.format(
            bucket_name=bucket.name,
            image=keys[0].name
        ) if keys else ''
    return render_template('index.html', current_image=get_image())


def main():
    """
    Main entry point for script.
    """
    app.run(debug=True)


if __name__ == '__main__':
    sys.exit(main())