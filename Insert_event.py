import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from flask import Flask , url_for , render_template 
import requests
import os
from forms import RegistrationForm,LoginForm


scopes = ['https://www.googleapis.com/auth/calendar']
service = 'calendar'
version = 'v3'


app = Flask(__name__)

app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

@app.route('/')
def home_page():
	redirect = url_for('register_page',_external = True)
	return '<h1>for login click <a href = "{}">here</a></h1>'.format(redirect)

@app.route('/register')
def register_page():
	form =  RegistrationForm()
	return render_template('register_page.html',form = form,
		title = 'Register')

@app.route('/login')
def login_page():
	form =  LoginForm()
	return render_template('login_page.html',form = form,
		title = 'Login')


@app.route('/event/')
def event():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  cal = googleapiclient.discovery.build(
      service, version, credentials=credentials)
  """
  event = {
  	'summary': '{}'.format(),
  	'description': '{}'.format(Des),
	'start': 
	    {
	    'dateTime': '{}+05:30'.format(startT)
	    },
	'end' : 
	    {
	    'dateTime': '{}+05:30'.format(endT)
	    }
	}
  event = cal.events().insert(calendarId='primary', body=event).execute()
	"""
  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.jsonify(**files)


@app.route('/authorize/')
def authorize():

	flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=['https://www.googleapis.com/auth/calendar'])  #creating flow object

	flow.redirect_uri = 'http://c3cd56b4.ngrok.io' #redirect uri

	authorization_url, state = flow.authorization_url(
    # Enable offline access so that you can refresh an access token without
    # re-prompting the user for permission. Recommended for web server apps.
    access_type='online',
    # Enable incremental authorization. Recommended as a best practice.
    include_granted_scopes='true')


	# Store the state so the callback can verify the auth server response.
	flask.session['state'] = state
	return flask.redirect( authorization_url )

@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))



def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run(port=21001, use_reloader=True, debug=True)
