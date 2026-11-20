import { options, render, type ComponentType, type VNode } from 'preact';

import { App } from './components/app/App';

import './styles/base.css';
import './styles/designs.css';

// Preact 11 leaves `ref` on class-component props and does not attach it to the
// instance. Terminal is controlled through that ref (send, fit, selection).
const previousVNodeHook = options.vnode;
options.vnode = (vnode) => {
  if (isClassComponent(vnode.type) && hasRefProp(vnode.props)) {
    vnode.ref = vnode.props.ref;
    delete vnode.props.ref;
  }
  previousVNodeHook?.(vnode);
};

function isClassComponent(type: VNode['type']): type is ComponentType {
  if (typeof type !== 'function') return false;
  const prototype = (type as { prototype?: { render?: unknown } }).prototype;
  return typeof prototype?.render === 'function';
}

function hasRefProp(props: object): props is { ref?: VNode['ref'] } {
  return 'ref' in props;
}

const root = document.getElementById('app');
if (!root) throw new Error('Missing #app root');

render(<App />, root);

