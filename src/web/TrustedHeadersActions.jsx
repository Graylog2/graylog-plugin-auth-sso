import Reflux from 'reflux';

const TrustedHeadersActions = Reflux.createActions({
  config: { asyncResult: true },
  saveConfig: { asyncResult: true },
});

export default TrustedHeadersActions;
