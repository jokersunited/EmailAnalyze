 ==================================================================================================================
|    ______                 _ _   _    _                _                                  _                      |
|   |  ____|               (_) | | |  | |              | |               /\               | |                     |
|   | |__   _ __ ___   __ _ _| | | |__| | ___  __ _  __| | ___ _ __     /  \   _ __   __ _| |_   _ _______ _ __   |
|   |  __| | '_ ` _ \ / _` | | | |  __  |/ _ \/ _` |/ _` |/ _ \ '__|   / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|  |
|   | |____| | | | | | (_| | | | | |  | |  __/ (_| | (_| |  __/ |     / ____ \| | | | (_| | | |_| |/ /  __/ |     |
|   |______|_| |_| |_|\__,_|_|_| |_|  |_|\___|\__,_|\__,_|\___|_|    /_/    \_\_| |_|\__,_|_|\__, /___\___|_|     |
|                                                                                             __/ |               |
|                                                                                            |___/                |
|  Done by: Joshua Wee for CSA 											  |
==================================================================================================================

**** Current Features ****

1) SPF, DKIM, DMARC checks
2) Domain Alignment checks (To vs Return-Path)
3) IP relay blacklist check
4) Homoglyph percentage on body text
5) Phsihing words body text check for categorization and scoring
6) IP relay tracing
5) Body URL link checks

**************************

=== Pre-requsites ===

Python3 & Python3 pip installer

=== Installation steps ===

1) $pip install -r requirements.txt
	- All python dependencies are stored in requirements.txt 
2) Replace line 111 of C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python38-32\Lib\homoglyphs\core.py with "open(cls.fpath, encoding='utf-8') as f:"
3) Replace confusables.json file at same folder (\homoglyphs) with the file provided in installation files folder

=== Using the application ===

1) Run the program using the command line "$python3 emailUI.py"
2) Browser will automatically be opened with the UI (Or access the UI using "http://localhost:5000")
3) Upload your ZIP file with all the email headers using the UI (Some examples are provided in the EMAIL EXAMPLES folder)

=== Known Issues (14/8/2020) ===

1) Individual files (.eml/.txt) do not work, if necessary ZIP them before uploading them
2) Domain and Certificate information not parsed properly yet, displayed as raw object form
3) Phishing score on individual email overview page is currently just a placeholder
4) Certain emails have malformed URLs causing the body URL checks to not display information correctly