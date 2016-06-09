## Authorization of Koha patrons for 3rd party 
This script enables 3rd parties to authorize patrons of a koha library. 

For example the patron logs in in the German onleihe (ebook portal) with its koha credentials and the 3rd party checks against this script to see:
- if the user exists
- if the credentials are matching
- age 

### Installation

Place this file in /YOURPATHTOKOHA/opac/cgi-bin/opac so it will be accessible under https://yourkoha/cgi-bin/koha/onleihe_auth.pl
You can rename it to your needs, making it harder to run attacks on it.

### Important
Make sure this script is only requested by POST-requests and that the domain runs in https. If the 3rd party uses the GET-requests, the user credentials will be visible in the server logs.

If you use this method of authorization, the username and password will be handled by the 3rd party, therefore it needs to be trustworthy! 
