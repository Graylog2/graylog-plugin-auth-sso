import Reflux from 'reflux';

import SsoAuthActions from 'SsoAuthActions';

import UserNotification from 'util/UserNotification';
import URLUtils from 'util/URLUtils';
import fetch from 'logic/rest/FetchProvider';

const urlPrefix = '/plugins/org.graylog.plugins.auth.sso';

const SsoAuthStore = Reflux.createStore({
  listenables: [SsoAuthActions],

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
    }, this._errorHandler('Fetching config failed', 'Could not retrieve SSO authenticator config'));

    SsoAuthActions.config.promise(promise);
  },

  saveConfig(config) {
    const promise = fetch('PUT', this._url('/config'), config);

    promise.then((response) => {
      this.trigger({ config: response });
      UserNotification.success('SSO configuration was updated successfully');
    }, this._errorHandler('Updating SSO config failed', 'Unable to update SSO authenticator config'));

    SsoAuthActions.saveConfig.promise(promise);
  },
});

export default SsoAuthStore;