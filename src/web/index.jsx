import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import TrustedHttpHeadersConfig from "./TrustedHttpHeadersConfig";

PluginStore.register(new PluginManifest(packageJson, {
  /* This is the place where you define which entities you are providing to the web interface.
     Right now you can add routes and navigation elements to it.

     Examples: */

  // Adding a route to /sample, rendering YourReactComponent when called:

  // routes: [
  //  { path: '/sample', component: YourReactComponent, permissions: 'INPUTS_CREATE' },
  // ],

  // Adding an element to the top navigation pointing to /sample named "Sample":

  // navigation: [
  //  { path: '/sample', description: 'Sample' },
  // ]
  authenticatorConfigurations: [
    {
      name: 'trusted-headers',
      displayName: 'Trusted HTTP Headers',
      description: 'Creates and authenticates users based on HTTP headers set by a proxy, useful for SSO systems',
      canBeDisabled: true,
      component: TrustedHttpHeadersConfig,
    },
  ]
}));
