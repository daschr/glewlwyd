import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class Navbar extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "profile",
      loggedIn: props.loggedIn,
      schemeList: props.schemeList,
      profileList: props.profileList
    }

    messageDispatcher.subscribe('Navbar', (message) => {
    });
    
    this.navigate = this.navigate.bind(this);
    this.toggleLogin = this.toggleLogin.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.changeProfile = this.changeProfile.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      loggedIn: nextProps.loggedIn, 
      schemeList: nextProps.schemeList,
      profileList: nextProps.profileList
    });
  }
  
  navigate(e, page, type) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "nav", page: page, module: type});
    this.setState({curNav: page});
  }

  toggleLogin() {
    if (this.state.loggedIn) {
      apiManager.glewlwydRequest("/auth/?username=" + encodeURI(this.state.profileList[0].username), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    } else {
      var schemeDefault = "";
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_default) {
          scheme.scheme_default.forEach((page) => {
            if (page === "admin") {
              schemeDefault = scheme.scheme_name;
            }
          });
        }
      });
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURI([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURI(this.state.config.profile_scope) + "&scheme=" + encodeURI(schemeDefault);
    }
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
      messageDispatcher.sendMessage('App', {type: "lang"});
    });
  }
  
  changeProfile(e, profile) {
    apiManager.glewlwydRequest("/auth/", "POST", {username: profile.username})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: "profile"});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
    });
  }

	render() {
    var langList = [], schemeList = [], profileList = [];
    var profileDropdown;
    ["en","fr"].forEach((lang, i) => {
      if (lang === i18next.language) {
        langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
      } else {
        langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
      }
    });
    this.state.schemeList.forEach((scheme, index) => {
      if (scheme.module !== "retype-password") { // Because scheme retype-password has no user configuration
        schemeList.push(
          <li className={"nav-item" + (this.state.curNav===scheme.name?" active":"")} key={index}>
            <a className="nav-link" href="#" onClick={(e) => this.navigate(e, scheme.name, scheme.module)}>{scheme.display_name||scheme.name}</a>
          </li>
        );
      }
    });
    var passwordJsx, sessionJsx;
    if (!this.state.config.params.delegate && this.state.profileList) {
      passwordJsx = <li className={"nav-item" + (this.state.curNav==="password"?" active":"")}>
        <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "password", null)}>{i18next.t("profile.menu-password")}</a>
      </li>
    }
    if (this.state.profileList) {
      sessionJsx = <li className={"nav-item" + (this.state.curNav==="session"?" active":"")}>
        <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "session", null)}>{i18next.t("profile.menu-session")}</a>
      </li>
    }
    if (this.state.profileList) {
      this.state.profileList.forEach((profile, index) => {
        profileList.push(<a className={"dropdown-item"+(!index?" active":"")} href="#" onClick={(e) => this.changeProfile(e, profile)} key={index}>{profile.name||profile.username}</a>);
      });
    }
    if (profileList.length) {
      profileDropdown = 
      <div className="btn-group" role="group">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownProfile" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i className="fas fa-user"></i>
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownProfile">
          {profileList}
        </div>
      </div>
    }
		return (
      <nav className="navbar navbar-expand-lg navbar-light bg-light">
        <a className="navbar-brand" href="#">Glewlwyd</a>
        <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarSupportedContent">
          <ul className="navbar-nav mr-auto">
            <li className={"nav-item" + (this.state.curNav==="profile"?" active":"")}>
              <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "profile", null)}>{i18next.t("profile.menu-user")}</a>
            </li>
            {sessionJsx}
            {passwordJsx}
            {schemeList}
          </ul>
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-globe-africa"></i>
              </button>
              <div className="dropdown-menu" aria-labelledby="dropdownLang">
                {langList}
              </div>
            </div>
            {profileDropdown}
            <button type="button" className="btn btn-secondary" onClick={this.toggleLogin}>
              <i className="fas fa-sign-in-alt btn-icon"></i>
            </button>
          </div>
        </div>
      </nav>
		);
	}
}

export default Navbar;
