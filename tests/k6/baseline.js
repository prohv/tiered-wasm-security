import http from 'k6/http';
import { check } from 'k6';

const targetUrl = __ENV.TARGET_URL || 'http://waf_envoy:10000/api/test';
const payloadSize = parseInt(__ENV.PAYLOAD_SIZE || '4096');
const duration = __ENV.TEST_DURATION || '5s';
const vus = parseInt(__ENV.VUS || '10');

export const options = {
  vus: vus,
  duration: duration,
};

const payloadData = JSON.stringify({
  data: 'B'.repeat(Math.max(0, payloadSize - 20)),
  timestamp: Date.now(),
});

export default function () {
  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const res = http.post(targetUrl, payloadData, params);

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
