// eslint-disable-next-line no-unused-vars
import webpackEntry from 'webpack-entry';

import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import SsoConfiguration from "./SsoConfiguration";

PluginStore.register(new PluginManifest(packageJson, {
  authenticatorConfigurations: [
    {
      name: 'sso',
      displayName: 'Single Sign-On (SSO)',
      description: 'Creates and authenticates users based on HTTP headers set by an authentication proxy to integrate with SSO systems',
      canBeDisabled: true,
      component: SsoConfiguration,
    },
  ]
}));
