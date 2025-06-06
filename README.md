# OSINT Tool

## Description
This is a command-line OSINT (Open Source Intelligence) tool designed to gather various types of publicly available information about a given domain or username. It performs WHOIS lookups, DNS record resolution, GeoIP lookups, social media presence checks, data breach searches (HaveIBeenPwned), Hunter.io email discovery, and reverse image search URL generation.

The tool includes robust error handling, retry mechanisms for HTTP requests, and color-coded logging for better user experience.

## Features
- WHOIS lookup using `python-whois` library and system `whois` command fallback.
- DNS record retrieval for A, MX, NS, TXT, SPF, and DKIM records.
- GeoIP lookup using ipinfo.io API.
- Social media profile discovery on popular platforms (Twitter, GitHub, Instagram, LinkedIn, Facebook).
- Data breach lookup with HaveIBeenPwned API.
- Email discovery via Hunter.io API.
- Reverse image search URL generation for Google.
- Colorful and informative logging output.
- Retry mechanism for HTTP requests with exponential backoff.
- Command-line interface with input validation.
- Output results saved in JSON format.

## Requirements
- Python 3.7+
- Packages listed in `requirements.txt`:
  - whois
  - requests
  - validators
  - dnspython
  - python-dotenv
  - pygments

## Installation
1. Clone or download the repository.
2. Create and activate a virtual environment (optional but recommended):

   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\\Scripts\\activate   # Windows
 
## Install dependencies

pip install -r requirements.txt

## Create a .env file in the project directory and add your API keys

HIBP_API_KEY=your_haveibeenpwned_api_key
HUNTER_API_KEY=your_hunter_io_api_key

## Usage

Run the script with the target domain or username as the main argument:

python OSINT.py target [--image IMAGE_URL] [--output OUTPUT_FILENAME] [--verbose]

## Arguments

*   target : Domain name or username to investigate.
*    --image IMAGE_URL : Optional URL of an image to generate a Google reverse image search link.
*    --output OUTPUT_FILENAME : Optional filename for saving results (default: osint_results_<target>.json).
*    --verbose : Enable verbose logging for debugging.

## Examples

python OSINT.py example.com --verbose
python OSINT.py johndoe --output results.json
python OSINT.py example.com --image https://example.com/image.jpg

## Notes

* Ensure you have valid API keys for HaveIBeenPwned and Hunter.io services set in your .env file.
* The system whois command must be installed and accessible for fallback WHOIS lookups.
* The tool respects rate limits by using retries with exponential backoff.
* Outputs are saved in JSON format for easy parsing and further analysis.

## License

This project is open source and free to use.