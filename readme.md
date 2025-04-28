🛡️ ArmorCode Findings Dashboard
A Streamlit-based interactive dashboard for viewing, filtering, deduplicating, and exporting findings from ArmorCode via API.
It supports async fetching, fuzzy clustering, grouping, CVE linking, and Excel export.

✨ Features
Load findings from ArmorCode API asynchronously

Interactive filters: Severity, Environment, SLA breach, Components

Multiple deduplication strategies (Component, Title, CVE, Custom)

Group findings dynamically

Fuzzy clustering of similar findings

SLA breach identification

Visualizations: Findings by source

Export results to Excel with multiple sheets

🚀 Getting Started
Prerequisites
Make sure you have Python 3.8+ installed.

Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/armorcode-dashboard.git
cd armorcode-dashboard
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Set your ArmorCode API Key:

Place your API key inside a file named ArmorCode_API_key.txt in the project root:

bash
Copy
Edit
echo "YOUR_API_KEY_HERE" > ArmorCode_API_key.txt
🖥️ Running the Dashboard
bash
Copy
Edit
streamlit run app.py
Replace app.py with your actual Python file if it has a different name.

The app will open automatically in your default web browser.

📂 Project Structure
graphql
Copy
Edit
armorcode-dashboard/
│
├── app.py               # Main Streamlit dashboard
├── requirements.txt      # Python dependencies
├── ArmorCode_API_key.txt # Your ArmorCode API Key (local, not committed)
└── README.md             # This file
⚙️ Main Technologies Used
Streamlit

Pandas

Aiohttp

Fuzzywuzzy

st-aggrid

Matplotlib

🛠️ Customization
Modify the deduplication strategies inside deduplicate_findings()

Tune fuzzy clustering thresholds in fuzzy_group_findings()

Add more filters in the Streamlit sidebar if needed

📝 License
This project is licensed under the MIT License — feel free to use and modify!

🤝 Contributing
Pull requests are welcome.
For major changes, please open an issue first to discuss what you would like to change.

