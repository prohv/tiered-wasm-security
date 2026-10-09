import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const targetUrl = __ENV.TARGET_URL || 'http://waf_envoy:10000/api/test';
const payloadSize = parseInt(__ENV.PAYLOAD_SIZE || '16384');
const duration = __ENV.TEST_DURATION || '5s';
const vus = parseInt(__ENV.VUS || '10');

export const paddedAttacksSent = new Counter('padded_attacks_sent');
export const truncationBlocked = new Counter('truncation_blocked');

export const options = {
  vus: vus,
  duration: duration,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
};

// Attack payload positioned past the 4096-byte inspection window
// Front 4096 bytes are benign padding
const attackSignature = "'; DROP TABLE sensitive_records; --";
const paddingSize = Math.max(0, payloadSize - attackSignature.length - 50);
const paddedPayload = JSON.stringify({
  padding: 'P'.repeat(paddingSize),
  malicious_tail: attackSignature,
});

export default function () {
  paddedAttacksSent.add(1);

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-Attack': '1', // Metadata escalation trigger
      'X-Padded-Attack': 'true',
    },
  };

  const res = http.post(targetUrl, paddedPayload, params);

  const blocked = res.status === 403;
  if (blocked) {
    truncationBlocked.add(1);
  }

  check(res, {
    'truncation safety policy enforced (403)': (r) => r.status === 403,
    'inspection status is partially inspected': (r) =>
      r.headers['X-Waf-Inspection-Status'] === 'PARTIALLY_INSPECTED',
  });
}
