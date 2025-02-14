import React from 'react';
import ReactDOM from 'react-dom';
import Backend from '../js/i18nextXHRBackend';
import LanguageDetector from '../js/i18nextBrowserLanguageDetector';

import apiManager from './lib/APIManager';
import App from './Login/App';

var getParameterByName = function (name, url) {
  if (!url) url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'), results = regex.exec(url);
  if (!results)
    return null;
  if (!results[2])
    return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
};

var initApp = () => {
  apiManager.request("config.json")
  .then((frontEndConfig) => {
    apiManager.request(frontEndConfig.GlewlwydUrl + "config/")
    .then((serverConfig) => {
      apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign({
        params: {
          scope: getParameterByName("scope")||false, 
          client_id: getParameterByName("client_id")||false, 
          callback_url: getParameterByName("callback_url")||false,
          scheme: getParameterByName("scheme")||false,
          prompt: getParameterByName("prompt")||false,
          refresh_login: !!getParameterByName("refresh_login"),
          login_hint: getParameterByName("login_hint")||false
        }
      }, frontEndConfig, serverConfig);
      ReactDOM.render(<App config={config}/>, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false}/>, document.getElementById('root'));
    });
  });
}

var i18nextOpt = {
  fallbackLng: 'en',
  ns: ['translations'],
  defaultNS: 'translations',
  backend: {
    loadPath: 'locales/{{lng}}/{{ns}}.json'
  }
};

if (getParameterByName("ui_locales")) {
  i18nextOpt.lng = getParameterByName("ui_locales").split(" ")[0];
}

i18next
.use(Backend)
.use(LanguageDetector)
.init(i18nextOpt)
.then(() => {
  initApp()
});
