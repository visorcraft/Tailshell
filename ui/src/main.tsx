import { render } from 'preact';

import { App } from './components/app/App';

import './styles/base.css';
import './styles/designs.css';

const root = document.getElementById('app');
if (!root) throw new Error('Missing #app root');

render(<App />, root);

