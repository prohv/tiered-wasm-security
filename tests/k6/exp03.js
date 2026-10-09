import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const targetUrl = __ENV.TARGET_URL || 'http://waf_envoy:10000/api/test';
const payloadSize = parseInt(__ENV.PAYLOAD_SIZE || '4096');
const duration = __ENV.TEST_DURATION || '5s';
const vus = parseInt(__ENV.VUS || '10');

export const attacksSent = new Counter('attacks_sent');
export const attacksBlocked = new Counter('attacks_blocked');
export const benignSent = new Counter('benign_sent');
export const benignAllowed = new Counter('benign_allowed');

export const options = {
  vus: vus,
  duration: duration,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
};

const benignPayload = JSON.stringify({
  data: 'B'.repeat(Math.max(0, payloadSize - 30)),
  type: 'benign',
});

const attackPayload = JSON.stringify({
  data: 'B'.repeat(Math.max(0, payloadSize - 100)),
  query: "'; drop table users; --",
  type: 'attack',
});

export default function () {
  const isAttack = Math.random() < 0.10;

  if (isAttack) {
    attacksSent.add(1);
    const params = {
      headers: {
        'Content-Type': 'application/json',
        'X-Attack': '1',
        'X-Is-Attack': 'true',
      },
    };
    const res = http.post(targetUrl, attackPayload, params);
    if (res.status === 403) {
      attacksBlocked.add(1);
    }
    check(res, {
      'attack blocked (403)': (r) => r.status === 403,
    });
  } else {
    benignSent.add(1);
    const params = {
      headers: {
        'Content-Type': 'application/json',
      },
    };
    const res = http.post(targetUrl, benignPayload, params);
    if (res.status === 200) {
      benignAllowed.add(1);
    }
    check(res, {
      'benign allowed (200)': (r) => r.status === 200,
    });
  }
}
