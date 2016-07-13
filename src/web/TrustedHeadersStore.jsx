import Reflux from 'reflux';

import TrustedHeadersActions from 'TrustedHeadersActions';

import UserNotification from 'util/UserNotification';
import URLUtils from 'util/URLUtils';
import fetch from 'logic/rest/FetchProvider';

const urlPrefix = '/plugins/org.graylog.plugins.auth.httpheaders';

const TrustedHeadersStore = Reflux.createStore({
  listenables: [TrustedHeadersActions],

  getInitialState() {
    return {
      config: undefined,
    };
  },

  _errorHandler(message, title, cb) {
    return (error) => {
      let errorMessage;
      try {
        errorMessage = error.additional.body.message;
      } catch (e) {
        errorMessage = error.message;
      }
      UserNotification.error(`${message}: ${errorMessage}`, title);
      if (cb) {
        cb(error);
      }
    };
  },

  _url(path) {
    return URLUtils.qualifyUrl(`${urlPrefix}${path}`);
  },

  config() {
    const promise = fetch('GET', this._url('/config'));

    promise.then((response) => {
      this.trigger({ config: response });
    }, this._errorHandler('Fetching config failed', 'Could not retrieve trusted HTTP headers authenticator config'));

    TrustedHeadersActions.config.promise(promise);
  },

  saveConfig(config) {
    const promise = fetch('PUT', this._url('/config'), config);

    promise.then((response) => {
      this.trigger({ config: response });
      UserNotification.success('trusted HTTP headers authenticator configuration was updated successfully');
    }, this._errorHandler('Updating authenticator config failed', 'Unable to update trusted HTTP headers authenticator config'));

    TrustedHeadersActions.saveConfig.promise(promise);
  },
});

export default TrustedHeadersStore;