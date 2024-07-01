# Here is the functionality of the Flask app. I am not sure how it works on other machines except

1. After going into the Google Cloud interface one creates an App with the capability to get access to 
Google Account namely G-mail, reading and writing and downloading from it. 

2. Generates Clinet_secrets.json which is stored here in the app folder but again Im not sure if it 
will work on other machines

3. Download the required packages using pip install for each one listed in the requirements.txt

4. It is advised to start a virtual environment using venv/scripts/activate

5. After runnind flas run it will be hosted on http://localhost:5000. When clicking it it should 
automatically redirect to the /authorize root which will then show a page asking for verification from 
your google account to access your info. If things go correctly, it will redirect to a page saying
"Your email address is (insertyouremailhere)"

6. Begin using he various routes to use the flask app. To begin you can access /emails but to properly 
access it, it will need to format the url correctly like this: 
emails?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
Where YYYY is the year, MM is month and DD is day. Months or days below 10 must start with 0.
The emails will be returned in a JSON

7. When using the /download_attachments route, the app will download every attachment in the specified
date range to a /downloads folder within the app. Info on the attachments will also be saved to attachmentinfo.json
Running the endpoint again clears both all attachments in the folder and the JSON.
Be forewarned as a large enough date range might take quite a while for the app to download and process

8. Use /revoke to revoke permission from the app to use your Google Account.Or /clear to clear them