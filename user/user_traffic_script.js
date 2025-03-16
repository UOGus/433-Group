import http from 'k6/http'
import { sleep } from 'k6'

export const options = {
  discardResponseBodies: true,
  scenarios: {
    contacts: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 10 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '0s',
    },
  },
};

export default function() {
    http.get('http://10.9.0.5:8080/')

    sleep(0.5)
}