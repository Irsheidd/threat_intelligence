import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.app import app


def main():
    sample_logs = [
        "2026-05-04T09:06:05,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,820,suspicious,suspicious",
        "2026-05-04T09:06:06,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,810,suspicious,suspicious",
        "2026-05-04T09:06:07,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,success,900,access,suspicious",
        "2026-05-04T09:06:08,user_45,sess_025,192.168.1.65,10.0.0.7,US,data_transfer,POST,success,13000,exfiltration,suspicious",
    ]

    with app.test_client() as client:
        response = client.post('/detect', json={'logs': sample_logs})
        print('Status:', response.status_code)
        payload = response.get_json()
        print('Response JSON:', payload)

        alerts_response = client.get('/api/alerts')
        print('Alerts Status:', alerts_response.status_code)
        print('Alerts JSON:', alerts_response.get_json())


if __name__ == '__main__':
    main()
