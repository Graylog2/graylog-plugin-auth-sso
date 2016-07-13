import Reflux from 'reflux';

const SsoAuthActions = Reflux.createActions({
  config: { asyncResult: true },
  saveConfig: { asyncResult: true },
});

export default SsoAuthActions;
