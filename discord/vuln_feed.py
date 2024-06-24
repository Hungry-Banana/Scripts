from datetime import datetime, time, date, timedelta, timezone
import requests
import time as timey

class CVE:
	def __init__(self, cve_id):
		self.cve_id = cve_id
		self.description = ''
		self.severity = ''
		self.link = ''
		self.vuln_Status = ''
		self.published = ''

def postDiscord(cve, discord_channel, bot_token):
	url = f"https://discord.com/api/channels/{discord_channel}/messages"

	headers = {
	'Content-Type': 'application/json',
	"Authorization": f"Bot {bot_token}"
	}

	json_data = {
		'embeds': [
			{
				'title': f"{cve.cve_id} - {cve.severity}",
				'url': cve.link,
				'color': severity_color[cve.severity],
				'fields': [
					{
						'name' : f"Status: {cve.vuln_Status}",
						'value': cve.description,
					},
				],
				"footer":{
					"text": f"Date Published: {cve.published}"
				}
			},
		],
	}

	response = requests.post(
		url,
		headers=headers,
		json=json_data,
	)

	status_codes = [200, 204]
	if response.status_code not in status_codes :
		if int(response.headers['X-RateLimit-Remaining']) <= 2:
			print(f"Hit rate limit wiating {int(response.headers['X-RateLimit-Reset']) - timey.time()}")
			timey.sleep(int(response.headers['X-RateLimit-Reset']) - timey.time())

def condition(cve):
	match cve.severity:
		case "CRITICAL":
			return 1
		case "HIGH":
			return 2
		case "MEDIUM":
			return 3
		case "LOW":
			return 4
		case _:
			return 5

start_of_today = datetime.combine(date.today(), time())
start_of_yesterday = (start_of_today - timedelta(hours = 24))

gpu_list = ['nvidia']
linux_os_list = ['ubuntu', 'fedora', 'debian', 'mint', 'suse', 'redhat']
windows_os_list = ['windows']

all_cve_list = []
gpu_cve_list = []
linux_cve_list = []
windows_cve_list = []

bot_auth_token = 'auth_token_goes_here'
severity_color = {"CRITICAL":16711680, "HIGH":16711680, "MEDIUM":16744448, "LOW":16776960}

vuln_feed_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start_of_yesterday.isoformat()}&pubEndDate={start_of_today.isoformat()}"
vuln_channel_all = "1"
vuln_channel_nvidia = "12"
vuln_channel_windows = "123"
vuln_channel_linux = "1234"

r = requests.get(vuln_feed_url)

data = r.json()

for vulnerability in data['vulnerabilities']:
	cve = CVE(vulnerability['cve']['id'])
	cve.vuln_Status = vulnerability['cve']['vulnStatus']
	cve.link = f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
	cve.published = vulnerability['cve']['published']

	for description in vulnerability['cve']['descriptions']:
		if description['lang'] == 'en':
			cve.description = description['value']

	if 'cvssMetricV31' in vulnerability['cve']['metrics']:
		for metric in vulnerability['cve']['metrics']['cvssMetricV31']:
			cve.severity = metric['cvssData']['baseSeverity']

	if cve.severity != '':
		all_cve_list.append(cve)
		if any(ext in cve.description.lower() for ext in gpu_list):
			gpu_cve_list.append(cve)

		if any(ext in cve.description.lower() for ext in linux_os_list):
			linux_cve_list.append(cve)

		if any(ext in cve.description.lower() for ext in windows_os_list):
			windows_cve_list.append(cve)

# Sort by severity
all_cve_list.sort(key=condition)
gpu_cve_list.sort(key=condition)
windows_cve_list.sort(key=condition)
linux_cve_list.sort(key=condition)

# Post to nvidia channel in discord
for cve in gpu_cve_list:
	postDiscord(cve, vuln_channel_nvidia, bot_auth_token)

# Post to Windows channel in discord
for cve in windows_cve_list:
	postDiscord(cve, vuln_channel_windows, bot_auth_token)

# Post to Windows channel in discord
for cve in linux_cve_list:
	postDiscord(cve, vuln_channel_linux, bot_auth_token)