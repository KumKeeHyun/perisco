import http from 'k6/http';
import { sleep } from 'k6';

// export const options = {
//     stages: [
//       { duration: '15s', target: 200 },
//       { duration: '2m', target: 200 },
//       { duration: '15s', target: 0 },
//     ],
//   };

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s', 
      duration: '30s',
      preAllocatedVUs: 20, // how large the initial pool of VUs would be
      maxVUs: 50, // if the preAllocatedVUs are not enough, we can initialize more
    },
  },
};

export default function () {
  http.get('http://192.168.49.2:30000');
}

