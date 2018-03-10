"""
Replacement for RUSA ACP brevet time calculator
(see https://rusa.org/octime_acp.html)

"""

import flask
import os
from flask import request, Flask, redirect, url_for, render_template, abort
import arrow  # Replacement for datetime, based on moment.js
import acp_times  # Brevet time calculations
import config
from pymongo import MongoClient
import logging

###
# Globals
###
app = flask.Flask(__name__)
CONFIG = config.configuration()
app.secret_key = CONFIG.SECRET_KEY


client = MongoClient('db', 27017)
db = client.time

###
# Pages
###


@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    return flask.render_template('calc.html')


@app.route('/submit', methods=['POST'])
def submit():
    # Get data
    open = request.form.getlist("open")
    close = request.form.getlist("close")
    km = request.form.getlist("km")
    begin_date = request.form.get("begin_date")
    begin_time = request.form.get("begin_time")
    distance = request.form.get("distance")

    if open[0] == '' :
        abort(404)

    for i in range(len(open)):
        if open[i] != '':
            item_doc = {
                'distance': distance,
                'begin_date': begin_date,
                'begin_time': begin_time,
                'km': km[i],
                'open': open[i],
                'close': close[i]
            }
            if int(distance) * 1.2 < float(km[i]):
                abort(404)
            db.time.insert_one(item_doc)

    return flask.render_template('calc.html')

@app.route("/display")
def display():
    _items = db.time.find()
    items = [item for item in _items]
    return render_template('display.html', items=items)



@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


###############
#
# AJAX request handlers
#   These return JSON, rather than rendering pages.
#
###############
@app.route("/_calc_times")
def _calc_times():
    """
    Calculates open/close times from miles, using rules
    described at https://rusa.org/octime_alg.html.
    Expects one URL-encoded argument, the number of miles.
    """
    app.logger.debug("Got a JSON request")
    km = request.args.get('km', 999, type=float)
    distance = request.args.get('distance', 999, type=int)
    start_time = request.args.get('start_time', 999, type=str)
    time = arrow.get(start_time, 'YYYY-MM-DD HH:mm')
    time = time.shift(hours=+8)  # Change timezone
    app.logger.debug("km={}".format(km))
    app.logger.debug("request.args: {}".format(request.args))
    open_time = acp_times.open_time(km, distance, time)
    close_time = acp_times.close_time(km, distance, time)
    result = {"open": open_time, "close": close_time}
    return flask.jsonify(result=result)

#############

app.debug = CONFIG.DEBUG
if app.debug:
    app.logger.setLevel(logging.DEBUG)

if __name__ == "__main__":
    print("Opening for global access on port {}".format(CONFIG.PORT))
    app.run(port=CONFIG.PORT, host="0.0.0.0")
