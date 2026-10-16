import {createApp} from '../lib/app.mjs';
import {getStore} from '../lib/firebase.mjs';

const app = createApp({getStore});
export default { fetch: app };
