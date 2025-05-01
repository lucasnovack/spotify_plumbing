# Spotify Plumbing

Spotify Plumbing is a web application that allows users to explore their Spotify listening habits. Built with Flask, it authenticates users via Spotify's API, fetches data through the Developer API, processes it using a Bronze–Silver–Gold pipeline, and displays insights in a modern, user-friendly interface.

# Features

+ **Authentication:**: Securely connect with Spotify to access user data.

+ **Data Pipeline:**: Fetches raw data (Bronze), processes it (Silver), and generates aggregated statistics (Gold).

+ **Dashboard:** Central hub to choose between our statistics.

# Why did i choose this stack?

Most of these tools are used in my company, and there was a small gap between my current skills and the tools that would be useful for my work. To bridge that gap, I decided to build this app to deepen my understanding of some key concepts—mainly related to Flask and Pandas.

# Is this a role model Data Project?

**NOPE!**

Most of the things used here are a bit of an overkill for a project like this—but it's been fun working with this stack.

# How to see this thing up and running?

First, you'll need to create your API keys directly from the [Spotify Developer Dashboard.](https://developer.spotify.com/documentation/web-api)

Then, fill in the .env file with your newly created keys. It should look like this:

``` env
SPOTIFY_CLIENT_ID=your_client_id
SPOTIFY_CLIENT_SECRET=your_client_secret
SPOTIFY_REDIRECT_URI=http://localhost:5000/callback
FLASK_SECRET_KEY=your_secret_key
```

Next, create a virtual environment and install the project requirements:

```bash

#Linux

python3 -m venv .venv
source .venv/bin/activate  

# Windows: 
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

Finally, run the project with:

``` bash

python run.py

```

**Voilá!**
Prepare to be *mildly* impressed by my frontend skills. /s
