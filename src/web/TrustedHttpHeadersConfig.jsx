import React from "react";
import Reflux from "reflux";
import { Row, Col, Input, Button } from "react-bootstrap";

import TrustedHeadersActions from "TrustedHeadersActions";
import TrustedHeadersStore from "TrustedHeadersStore";

import Spinner from "components/common/Spinner";
import PageHeader from "components/common/PageHeader";
import ObjectUtils from 'util/ObjectUtils';

const TrustedHttpHeadersConfig = React.createClass({
  mixins: [
    Reflux.connect(TrustedHeadersStore),
  ],

  componentDidMount() {
    TrustedHeadersActions.config();
  },

  _saveSettings(ev) {
    ev.preventDefault();
    TrustedHeadersActions.saveConfig(this.state.config);
  },

  _setSetting(attribute, value) {
    const newState = {};

    // Clone state to not modify it directly
    const settings = ObjectUtils.clone(this.state.config);
    settings[attribute] = value;
    newState.config = settings;
    this.setState(newState);
  },


  _bindChecked(ev, value) {
    this._setSetting(ev.target.name, typeof value === 'undefined' ? ev.target.checked : value);
  },

  _bindValue(ev) {
    this._setSetting(ev.target.name, ev.target.value);
  },

  render() {
    let content;
    if (!this.state.config) {
      content = <Spinner />;
    } else {
      content = (
        <Row>
          <Col lg={8}>
            <form id="trusted-headers-form" className="form-horizontal" onSubmit={this._saveSettings}>
              <fieldset>
                <legend className="col-sm-12">Header configuration</legend>
                <Input type="text" id="username_header" name="username_header" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" placeholder="Remote-User" label="Username Header"
                       value={this.state.config.username_header} help="HTTP header containing the implicitly trusted name of the Graylog user"
                       onChange={this._bindValue} required/>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">User creation</legend>
                <Input type="checkbox" label="Automatically create users"
                       help="Enable this if Graylog should automatically create a user account for externally authenticated users. If disabled, an administrator needs to manually create a user account."
                       wrapperClassName="col-sm-offset-3 col-sm-9"
                       name="auto_create_user"
                       checked={this.state.config.auto_create_user}
                       onChange={this._bindChecked}/>
                <Input type="text" id="fullname_header" name="fullname_header" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" placeholder="Fullname header" label="Full Name Header"
                       value={this.state.config.fullname_header} help="HTTP header containing the full name of user to create (defaults to the user name)."
                       onChange={this._bindValue} disabled={!this.state.config.auto_create_user}/>
                <Input type="text" id="email_header" name="email_header" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" placeholder="Email header" label="Email Header"
                       value={this.state.config.email_header} help="HTTP header containing the email address of user to create (defaults to 'username@localhost')."
                       onChange={this._bindValue} disabled={!this.state.config.auto_create_user}/>
                <Input id="default_group" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" label="Default User Role"
                       help="The default Graylog role determines whether a user created can access the entire system, or has limited access.">
                  <Row>
                    <Col sm={4}>
                      <select id="default_group" name="default_group" className="form-control" required
                              value={this.state.config.default_group}
                              onChange={this._bindValue} disabled={!this.state.config.auto_create_user}>

                        <option value="Reader">Reader - basic access</option>
                        <option value="Admin">Administrator - complete access</option>
                      </select>
                    </Col>
                  </Row>
                </Input>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">Store settings</legend>
                <div className="form-group">
                  <Col sm={9} smOffset={3}>
                    <Button type="submit" bsStyle="success">Save authenticator settings</Button>
                  </Col>
                </div>
              </fieldset>
            </form>
          </Col>
        </Row>
      );
    }

    return (
      <div>
        <PageHeader title="Trusted HTTP headers (SSO)" subpage>
          <span>Configuration page for the trusted HTTP headers authenticator.</span>
          {null}
        </PageHeader>
        {content}
      </div>
    );
  },
});

export default TrustedHttpHeadersConfig;
