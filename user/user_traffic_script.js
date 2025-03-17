import http from 'k6/http'
import { sleep } from 'k6'

export const options = {
  discardResponseBodies: true,
  scenarios: {
    contacts: {
      executor: "constant-vus",
      vus: 10,
      duration: "300s"
    },
  },
};

export default function() {
    http.get('http://10.9.0.5:8080/')

    sleep(0.5)
}