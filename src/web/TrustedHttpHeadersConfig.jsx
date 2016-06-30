import React, { PropTypes } from 'react';

const TrustedHttpHeadersConfig = React.createClass({
  propTypes: {
    config: PropTypes.object,
  },
  render() {
    return (<span>Configuration page for the trusted HTTP headers authenticator.</span>);
  },
});

export default TrustedHttpHeadersConfig;
