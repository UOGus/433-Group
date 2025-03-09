import http from 'k6/http'
import { sleep } from 'k6'

export const options = {
    discardResponseBodies: true,
    vus: 5,
    duration: "60s",
  };

export default function() {
    http.get('http://10.9.0.5:8080/')

    sleep(0.5)
}