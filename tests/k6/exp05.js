import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const targetUrl = __ENV.TARGET_URL || 'http://waf_envoy:10000/api/test';
const duration = __ENV.TEST_DURATION || '5s';
const vus = parseInt(__ENV.VUS || '10');

export const sqliSent = new Counter('sqli_sent');
export const sqliBlocked = new Counter('sqli_blocked');

export const xssSent = new Counter('xss_sent');
export const xssBlocked = new Counter('xss_blocked');

export const traversalSent = new Counter('traversal_sent');
export const traversalBlocked = new Counter('traversal_blocked');

export const benignSent = new Counter('benign_sent');
export const benignBlocked = new Counter('benign_blocked');

export const options = {
  vus: vus,
  duration: duration,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
};

const attackVectors = [
  {
    category: 'sqli',
    headers: { 'X-Attack': '1', 'X-Attack-Type': 'sqli' },
    payload: JSON.stringify({ query: "SELECT * FROM users WHERE '1'='1' UNION SELECT null, null--" }),
  },
  {
    category: 'xss',
    headers: { 'X-Attack': '1', 'X-Attack-Type': 'xss' },
    payload: JSON.stringify({ comment: "<script>alert('XSS-Exploit')</script>" }),
  },
  {
    category: 'traversal',
    headers: { 'X-Attack': '1', 'X-Attack-Type': 'traversal' },
    payload: JSON.stringify({ file: "../../../../etc/passwd" }),
  },
  {
    category: 'benign',
    headers: {},
    payload: JSON.stringify({ action: "checkout", item_id: 1042, quantity: 2, notes: "standard benign order" }),
  },
];

export default function () {
  const index = Math.floor(Math.random() * attackVectors.length);
  const vector = attackVectors[index];

  const headers = Object.assign(
    { 'Content-Type': 'application/json' },
    vector.headers
  );

  if (vector.category === 'sqli') sqliSent.add(1);
  else if (vector.category === 'xss') xssSent.add(1);
  else if (vector.category === 'traversal') traversalSent.add(1);
  else benignSent.add(1);

  const res = http.post(targetUrl, vector.payload, { headers: headers });

  if (res.status === 403) {
    if (vector.category === 'sqli') sqliBlocked.add(1);
    else if (vector.category === 'xss') xssBlocked.add(1);
    else if (vector.category === 'traversal') traversalBlocked.add(1);
    else benignBlocked.add(1);
  }

  if (vector.category === 'benign') {
    check(res, { 'benign passes (200)': (r) => r.status === 200 });
  } else {
    check(res, { 'attack blocked (403)': (r) => r.status === 403 });
  }
}
